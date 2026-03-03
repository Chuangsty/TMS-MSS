// import React, { useEffect, useMemo, useState } from "react";
// import {
//   Alert,
//   Button,
//   Container,
//   IconButton,
//   InputAdornment,
//   Paper,
//   TextField,
//   Typography,
// } from "@mui/material";

// import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
// import AddRoundedIcon from "@mui/icons-material/AddRounded";
// import EditOutlinedIcon from "@mui/icons-material/EditOutlined";

// import { api } from "../api/client";
// import "./ApplicationManagementPage.css";

// const PLACEHOLDER_APPS = [
//   {
//     id: 1,
//     title: "Application 1",
//     status: "XXXXX",
//     projectLead: "XXXXX",
//     startDate: "xx-xx-xxxx",
//     endDate: "xx-xx-xxxx",
//     description:
//       "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce sodales vitae ipsum as sagittis. Sed nisl ante, tincidunt ac augue tempor, lobortis pretium erat. Integer ultrices ut massa ut mollis. Phasellus fermentum egestas suscipit.",
//     tasksTodo: 13,
//   },
//   {
//     id: 2,
//     title: "Application 2",
//     status: "XXXXX",
//     projectLead: "XXXXX",
//     startDate: "xx-xx-xxxx",
//     endDate: "xx-xx-xxxx",
//     description:
//       "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce sodales vitae ipsum as sagittis. Sed nisl ante, tincidunt ac augue tempor, lobortis pretium erat. Integer ultrices ut massa ut mollis.",
//     tasksTodo: 0,
//   },
//   {
//     id: 3,
//     title: "Application 3",
//     status: "XXXXX",
//     projectLead: "XXXXX",
//     startDate: "xx-xx-xxxx",
//     endDate: "xx-xx-xxxx",
//     description:
//       "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce sodales vitae ipsum as sagittis. Sed nisl ante, tincidunt ac augue tempor.",
//     tasksTodo: 2,
//   },
// ];

// function MetaRow({ app }) {
//   return (
//     <div className="appMetaRow">
//       <span className="appMetaItem">Status: {app.status}</span>
//       <span className="appMetaSep">|</span>
//       <span className="appMetaItem">Project Lead: {app.projectLead}</span>
//       <span className="appMetaSep">|</span>
//       <span className="appMetaItem">Start date: {app.startDate}</span>
//       <span className="appMetaSep">|</span>
//       <span className="appMetaItem">End date: {app.endDate}</span>
//     </div>
//   );
// }

// export default function ApplicationManagementPage() {
//   const [q, setQ] = useState("");
//   const [errMsg, setErrMsg] = useState("");

//   // API data of created projects
//   const [apps, setApps] = useState();
//   useEffect(() => {
//     let ignore = false;

//     (async () => {
//       try {
//         const res = await api.get("/api/applications"); // adjust endpoint
//         if (!ignore) {
//           setApps(res.data.applications);
//         }
//       } catch (err) {
//         console.error(err);
//       }
//     })();

//     return () => {
//       ignore = true;
//     };
//   }, []);

//   // role gating for "Project Lead buttons"
//   const [me, setMe] = useState(null);
//   useEffect(() => {
//     let ignore = false;
//     (async () => {
//       try {
//         const res = await api.get("/api/auth/me");
//         if (!ignore) setMe(res.data.user);
//       } catch {
//         // if auth fails, keep buttons hidden
//         if (!ignore) setMe(null);
//       }
//     })();
//     return () => {
//       ignore = true;
//     };
//   }, []);

//   const roles = me?.roles || [];
//   const canProjectLeadActions = roles.includes("PROJECT_LEAD") || roles.includes("ADMIN");

//   const filtered = useMemo(() => {
//     const s = q.trim().toLowerCase();
//     if (!s) return apps;
//     return apps.filter((a) => {
//       const hay = `${a.title} ${a.status} ${a.projectLead} ${a.description}`.toLowerCase();
//       return hay.includes(s);
//     });
//   }, [apps, q]);

//   function onNewApp() {
//     // TODO: open modal / navigate to create page
//     setErrMsg("New App action not wired to backend yet.");
//   }

//   function onEditApp(appId) {
//     // TODO: open modal / navigate
//     setErrMsg(`Edit app ${appId} not wired to backend yet.`);
//   }

//   function onNewTask(appId) {
//     // TODO: open create task modal
//     setErrMsg(`New Task for app ${appId} not wired to backend yet.`);
//   }

//   return (
//     <Container maxWidth={false} disableGutters className="appsPageContainer">
//       {errMsg ? (
//         <Alert
//           severity="info"
//           className="appsPageAlert"
//           onClose={() => setErrMsg("")}
//         >
//           {errMsg}
//         </Alert>
//       ) : null}

//       <Paper className="appsCard">
//         <div className="appsHeaderRow">
//           <div>
//             <Typography className="appsTitle">Applications Dashboard</Typography>
//           </div>

//           {canProjectLeadActions ? (
//             <Button
//               variant="outlined"
//               startIcon={<AddRoundedIcon />}
//               className="appsNewAppBtn"
//               onClick={onNewApp}
//             >
//               New App
//             </Button>
//           ) : (
//             <div className="appsNewAppBtnPlaceholder" />
//           )}
//         </div>

//         <div className="appsToolsRow">
//           <TextField
//             size="small"
//             placeholder="Application"
//             value={q}
//             onChange={(e) => setQ(e.target.value)}
//             className="appsSearch"
//             slotProps={{
//               startAdornment: (
//                 <InputAdornment position="start">
//                   <SearchRoundedIcon />
//                 </InputAdornment>
//               ),
//             }}
//           />
//         </div>

//         <div className="appsList">
//           {filtered.map((app) => (
//             <Paper key={app.id} variant="outlined" className="appItem">
//               <div className="appItemTop">
//                 <Typography className="appTitle">{app.title}</Typography>

//                 <IconButton
//                   size="small"
//                   className="appEditBtn"
//                   onClick={() => onEditApp(app.id)}
//                 >
//                   <EditOutlinedIcon fontSize="small" />
//                 </IconButton>
//               </div>

//               <MetaRow app={app} />

//               <div className="appDescBox">{app.description}</div>

//               <div className="appBottomRow">
//                 <Typography className="appTasksTodo">
//                   Tasks to-do: {String(app.tasksTodo).padStart(2, "0")}
//                 </Typography>

//                 {canProjectLeadActions ? (
//                   <Button
//                     variant="outlined"
//                     size="small"
//                     startIcon={<AddRoundedIcon />}
//                     className="appNewTaskBtn"
//                     onClick={() => onNewTask(app.id)}
//                   >
//                     New Task
//                   </Button>
//                 ) : (
//                   <div className="appNewTaskBtnPlaceholder" />
//                 )}
//               </div>
//             </Paper>
//           ))}

//           {filtered.length === 0 ? (
//             <div className="appsEmpty">No applications found</div>
//           ) : null}
//         </div>
//       </Paper>
//     </Container>
//   );
// }
