import { takeTaskService, forfeitTaskService, submitTaskService, rejectTaskService, approveTaskService } from "../services/workflow.service.js";

export async function takeTaskController(req, res, next) {
  try {
    const task_id = req.params.taskId;
    const tasks = await takeTaskService({ task_id, actorUserId: req.user.id });

    res.json(tasks);
  } catch (err) {
    next(err);
  }
}

export async function forfeitTaskController(req, res, next) {
  try {
    const task_id = req.params.taskId;
    const tasks = await forfeitTaskService({ task_id, actorUserId: req.user.id });

    res.json(tasks);
  } catch (err) {
    next(err);
  }
}

export async function submitTaskController(req, res, next) {
  try {
    const task_id = req.params.taskId;
    const tasks = await submitTaskService({ task_id, actorUserId: req.user.id });

    res.json(tasks);
  } catch (err) {
    next(err);
  }
}

export async function rejectTaskController(req, res, next) {
  try {
    const task_id = req.params.taskId;
    const tasks = await rejectTaskService({ task_id, actorUserId: req.user.id });

    res.json(tasks);
  } catch (err) {
    next(err);
  }
}

export async function approveTaskController(req, res, next) {
  try {
    const task_id = req.params.taskId;
    const tasks = await approveTaskService({ task_id, actorUserId: req.user.id });

    res.json(tasks);
  } catch (err) {
    next(err);
  }
}
