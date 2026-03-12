import { pool } from "../config/db.js";

// START helper functions ==============================

// 1) retrieve task states
async function getTaskStateRow(conn, slug) {
  const [[taskState]] = await conn.query(
    `
        SELECT id, task_state_name
        FROM task_states
        WHERE slug = ?
        LIMIT 1
        `,
    [slug],
  );
  if (!taskState) {
    const err = new Error(`Task state ${slug} not found`);
    err.status = 500;
    throw err;
  }
  return taskState;
}

// 2) retrieve app states
async function getAppStateRow(conn, slug) {
  const [[state]] = await conn.query(
    `
        SELECT id, state_name
        FROM states
        WHERE slug = ?
        LIMIT 1
        `,
    [slug],
  );
  if (!state) {
    const err = new Error(`Application state ${slug} not found`);
    err.status = 500;
    throw err;
  }
  return state;
}

// 3) retrieve user
async function getUserRow(conn, userId) {
  const [[user]] = await conn.query(
    `
        SELECT id, username
        FROM users
        WHERE id = ?
        LIMIT 1
        `,
    [userId],
  );
  if (!user) {
    const err = new Error(`User not found`);
    err.status = 500;
    throw err;
  }
  return user;
}

// 4) timestamp for task note append(upon action)
function makeTimestamp() {
  return new Date().toLocaleString("sv-SE", { timeZone: "Asia/Singapore" });
}

// 5) task note append(upon action)
function appendNote(existingNote, line) {
  return existingNote ? `${existingNote}\n${line}` : line;
}

// 6) locks task row in db while transaction to prevent race condition
async function getLockedTask(conn, task_id) {
  const [[task]] = await conn.query(
    `
        SELECT
            t.task_id,
            t.app_id,
            t.plan_id,
            t.task_state_id,
            t.task_note,
            t.developer,
            ts.slug AS task_state_slug
        FROM tasks t
        JOIN task_states ts ON ts.id = t.task_state_id
        WHERE t.task_id = ?
        LIMIT 1
        FOR UPDATE
        `,
    [task_id],
  );
  if (!task) {
    const err = new Error("Task not found");
    err.status = 404;
    throw err;
  }
  return task;
}

// 7) retrieve task details
async function readTaskDetails(conn, task_id) {
  const [[task]] = await conn.query(
    `
    SELECT
      t.task_id,
      t.app_id,
      t.task_no,
      t.task_name,
      t.task_description,
      t.task_note,
      t.plan_id,
      p.plan_name,
      t.task_created_at,
      t.task_taken_at,
      t.task_update_at,
      ts.task_state_name AS task_state,
      ts.id AS task_state_id,

      c.id AS creator_id,
      c.username AS creator_username,

      d.id AS developer_id,
      d.username AS developer_username
    FROM tasks t
    JOIN task_states ts ON ts.id = t.task_state_id
    JOIN users c ON c.id = t.creator
    LEFT JOIN users d ON d.id = t.developer
    LEFT JOIN plans p ON p.plan_id = t.plan_id
    WHERE t.task_id = ?
    LIMIT 1
    `,
    [task_id],
  );
  return task;
}

// 8) Update application state to complete upon all tasks complete
async function updateApplicationCompletionState(conn, app_id) {
  const [[openTaskCountRow]] = await conn.query(
    `
    SELECT COUNT(*) AS open_task_count
    FROM tasks t
    JOIN task_states ts ON ts.id = t.task_state_id
    WHERE t.app_id = ?
      AND ts.slug <> 'CLOSED'
    `,
    [app_id],
  );

  const [[app]] = await conn.query(
    `
    SELECT app_id, state_id
    FROM applications
    WHERE app_id = ?
    LIMIT 1
    FOR UPDATE
    `,
    [app_id],
  );

  if (!app) return;

  const completedState = await getAppStateRow(conn, "COMPLETED");
  const ongoingState = await getAppStateRow(conn, "ON_GOING");

  const nextStateId = Number(openTaskCountRow.open_task_count) === 0 ? completedState.id : ongoingState.id;

  if (app.state_id !== nextStateId) {
    await conn.query(
      `
      UPDATE applications
      SET state_id = ?
      WHERE app_id = ?
      `,
      [nextStateId, app_id],
    );
  }
}
// 9) clean string value feature
function cleanString(value) {
  return String(value ?? "").trim();
}

// 10) application ownership check
async function taskCreator(conn, task_id) {
  const [[taskCreator]] = await conn.query(
    `
        SELECT task_id, creator
        FROM tasks
        WHERE task_id = ?
        LIMIT 1
        `,
    [task_id],
  );
  if (!taskCreator) {
    const err = new Error("Application not found");
    err.status = 404;
    throw err;
  }
  return taskCreator;
}

// END helper functions ================================

// Developer actions =================================================
// Take on task
export async function takeTaskService({ task_id, actorUserId }) {
  const cleanTaskId = cleanString(task_id);
  if (cleanTaskId === "") {
    const err = new Error("Task id is required");
    err.status = 400;
    throw err;
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const task = await getLockedTask(conn, cleanTaskId);
    const actor = await getUserRow(conn, actorUserId);
    const doingState = await getTaskStateRow(conn, "DOING");

    // Task conditions ==============================================
    // task plan check
    if (!task.plan_id) {
      const err = new Error("Only planned tasks can be taken");
      err.status = 400;
      throw err;
    }
    // task state to-do check
    if (task.task_state_slug !== "TODO") {
      const err = new Error("Only TODO tasks can be taken");
      err.status = 400;
      throw err;
    }
    // task developer check
    if (task.developer) {
      const err = new Error("Task is already taken by a developer");
      err.status = 409;
      throw err;
    }
    // End of task conditions =======================================

    // note for append
    const line = `[ ${makeTimestamp()}, Task state: ${doingState.task_state_name} ] Developer ${actor.username} took task.`;
    const nextNote = appendNote(task.task_note, line);

    // update task in db
    await conn.query(
      `
        UPDATE tasks
        SET
            developer = ?,
            task_state_id = ?,
            task_taken_at = CURRENT_TIMESTAMP,
            task_note = ?
        WHERE task_id = ?
        `,
      [actorUserId, doingState.id, nextNote, cleanTaskId],
    );

    // check for application state update
    await updateApplicationCompletionState(conn, task.app_id);

    // retrieve updated task details
    const updatedTask = await readTaskDetails(conn, cleanTaskId);
    await conn.commit();

    return {
      message: "Task taken successfully",
      task: updatedTask,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// Forfeit on task
export async function forfeitTaskService({ task_id, actorUserId }) {
  const cleanTaskId = cleanString(task_id);
  if (cleanTaskId === "") {
    const err = new Error("Task id is required");
    err.status = 400;
    throw err;
  }

  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const task = await getLockedTask(conn, cleanTaskId);
    const actor = await getUserRow(conn, actorUserId);
    const todoState = await getTaskStateRow(conn, "TODO");

    // Task conditions ==============================================
    // task state check
    if (task.task_state_slug !== "DOING") {
      const err = new Error("Only DOING tasks can be forfeited");
      err.status = 400;
      throw err;
    }
    // developer check
    if (!task.developer || Number(task.developer) !== Number(actorUserId)) {
      const err = new Error("You can only forfeit your own task");
      err.status = 403;
      throw err;
    }
    // End of task conditions =======================================

    // note for append
    const line = `[ ${makeTimestamp()}, Task state: ${todoState.task_state_name} ] Developer ${actor.username} forfeited task.`;
    const nextNote = appendNote(task.task_note, line);

    // update task in db
    await conn.query(
      `
      UPDATE tasks
      SET
        developer = NULL,
        task_state_id = ?,
        task_update_at = CURRENT_TIMESTAMP,
        task_note = ?
      WHERE task_id = ?
      `,
      [todoState.id, nextNote, cleanTaskId],
    );

    // check for application completion
    await updateApplicationCompletionState(conn, task.app_id);

    // retrieve updated task details
    const updatedTask = await readTaskDetails(conn, cleanTaskId);
    await conn.commit();

    return {
      message: "Task forfeited successfully",
      task: updatedTask,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// Submit task
export async function submitTaskService({ task_id, actorUserId }) {
  const cleanTaskId = cleanString(task_id);
  if (cleanTaskId === "") {
    const err = new Error("Task id is required");
    err.status = 400;
    throw err;
  }

  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const task = await getLockedTask(conn, cleanTaskId);
    const actor = await getUserRow(conn, actorUserId);
    const doneState = await getTaskStateRow(conn, "DONE");

    // Task conditions ==============================================
    // task state check
    if (task.task_state_slug !== "DOING") {
      const err = new Error("Only DOING tasks can be submitted");
      err.status = 400;
      throw err;
    }
    // developer check
    if (!task.developer || Number(task.developer) !== Number(actorUserId)) {
      const err = new Error("You can only submit your own task");
      err.status = 403;
      throw err;
    }
    // End of task conditions =======================================

    // note for append
    const line = `[ ${makeTimestamp()}, Task state: ${doneState.task_state_name} ] Developer ${actor.username} submitted task for review.`;
    const nextNote = appendNote(task.task_note, line);

    // update task in db
    await conn.query(
      `
      UPDATE tasks
      SET
        task_state_id = ?,
        task_update_at = CURRENT_TIMESTAMP,
        task_note = ?
      WHERE task_id = ?
      `,
      [doneState.id, nextNote, cleanTaskId],
    );

    // check for application completion
    await updateApplicationCompletionState(conn, task.app_id);

    // retrieve updated task details
    const updatedTask = await readTaskDetails(conn, cleanTaskId);
    await conn.commit();

    return {
      message: "Task submitted for review successfully",
      task: updatedTask,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}
// Developer actions end =============================================

// Project Lead actions ==============================================
// Reject task
export async function rejectTaskService({ task_id, actorUserId }) {
  const cleanTaskId = cleanString(task_id);
  if (cleanTaskId === "") {
    const err = new Error("Task id is required");
    err.status = 400;
    throw err;
  }

  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const task = await getLockedTask(conn, cleanTaskId);
    const actor = await getUserRow(conn, actorUserId);
    const taskcreator = await taskCreator(conn, cleanTaskId);
    const doingState = await getTaskStateRow(conn, "DOING");

    // Task conditions ==============================================
    // task state check
    if (task.task_state_slug !== "DONE") {
      const err = new Error("Only DONE tasks can be rejected");
      err.status = 400;
      throw err;
    }
    // project lead check taskOwnership
    if (!taskcreator.creator || Number(taskcreator.creator) !== Number(actorUserId)) {
      const err = new Error("You can only reject task that you've created");
      err.status = 403;
      throw err;
    }
    // End of task conditions =======================================

    // note for append
    const line = `[ ${makeTimestamp()}, Task state: ${doingState.task_state_name} ] Project Lead ${actor.username} reviewed task and rejected it.`;
    const nextNote = appendNote(task.task_note, line);

    // update task in db
    await conn.query(
      `
      UPDATE tasks
      SET
        task_state_id = ?,
        task_update_at = CURRENT_TIMESTAMP,
        task_note = ?
      WHERE task_id = ?
      `,
      [doingState.id, nextNote, cleanTaskId],
    );

    // check for application completion
    await updateApplicationCompletionState(conn, task.app_id);

    // retrieve updated task details
    const updatedTask = await readTaskDetails(conn, cleanTaskId);
    await conn.commit();

    return {
      message: "Task have been rejected",
      task: updatedTask,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// Approve task
export async function approveTaskService({ task_id, actorUserId }) {
  const cleanTaskId = cleanString(task_id);
  if (cleanTaskId === "") {
    const err = new Error("Task id is required");
    err.status = 400;
    throw err;
  }

  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const task = await getLockedTask(conn, cleanTaskId);
    const actor = await getUserRow(conn, actorUserId);
    const taskcreator = await taskCreator(conn, cleanTaskId);
    const closeState = await getTaskStateRow(conn, "CLOSED");

    // Task conditions ==============================================
    // task state check
    if (task.task_state_slug !== "DONE") {
      const err = new Error("Only DONE tasks can be approve");
      err.status = 400;
      throw err;
    }
    // project lead check taskOwnership
    if (!taskcreator.creator || Number(taskcreator.creator) !== Number(actorUserId)) {
      const err = new Error("You can only approve task that you've created");
      err.status = 403;
      throw err;
    }
    // End of task conditions =======================================

    // note for append
    const line = `[ ${makeTimestamp()}, Task state: ${closeState.task_state_name} ] Project Lead ${actor.username} reviewed task and approved it.`;
    const nextNote = appendNote(task.task_note, line);

    // update task in db
    await conn.query(
      `
      UPDATE tasks
      SET
        task_state_id = ?,
        task_update_at = CURRENT_TIMESTAMP,
        task_note = ?
      WHERE task_id = ?
      `,
      [closeState.id, nextNote, cleanTaskId],
    );

    // check for application completion
    await updateApplicationCompletionState(conn, task.app_id);

    // retrieve updated task details
    const updatedTask = await readTaskDetails(conn, cleanTaskId);
    await conn.commit();

    return {
      message: "Task have been approved",
      task: updatedTask,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}
// Project Lead actions end ==========================================
