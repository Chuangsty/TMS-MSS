import React, { useEffect, useState } from "react";
import { Box, Container, Typography, Paper, TextField, Button, Card, CardContent, IconButton, Stack, InputAdornment } from "@mui/material";

import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import SearchIcon from "@mui/icons-material/Search";

import { api } from "../api/client";

export default function ApplicationsDashboardPage() {
  const [apps, setApps] = useState([]);
  const [search, setSearch] = useState("");
  const [roles, setRoles] = useState([]);

  useEffect(() => {
    let ignore = false;

    async function loadData() {
      try {
        const me = await api.get("/api/auth/me");
        if (!ignore) {
          setRoles(me.data?.user?.roles ?? []);
        }

        const appsRes = await api.get("/api/apps");
        if (!ignore) {
          setApps(appsRes.data ?? []);
        }
      } catch (err) {
        console.error(err);
      }
    }

    loadData();

    return () => {
      ignore = true;
    };
  }, []);

  const isProjectLead = roles.includes("PROJECT_LEAD");

  const filteredApps = apps.filter((app) => app.app_name?.toLowerCase().includes(search.toLowerCase()));

  return (
    <Box sx={{ backgroundColor: "#f5f5f5", minHeight: "100vh", pt: 4 }}>
      <Container maxWidth="lg">
        {/* Page Title */}
        <Typography variant="h5" fontWeight="bold" sx={{ mb: 3 }}>
          Applications Dashboard
        </Typography>

        <Paper sx={{ p: 3 }}>
          {/* Top Row */}
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
            <Typography variant="h6">Applications</Typography>

            {isProjectLead && (
              <Button variant="outlined" startIcon={<AddIcon />}>
                New App
              </Button>
            )}
          </Stack>

          {/* Search */}
          <TextField
            fullWidth
            placeholder="Application"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ mb: 3 }}
            slotProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />

          {/* App Cards */}
          <Stack spacing={2}>
            {filteredApps.map((app) => (
              <Card key={app.app_acronym}>
                <CardContent>
                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                    <Box>
                      <Typography fontWeight="bold">{app.app_name}</Typography>

                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        Status: {app.state_name || "N/A"} | Project Lead: {app.project_lead_name || "N/A"} | Start date: {app.app_startDate} | End date: {app.app_endDate}
                      </Typography>

                      <Typography variant="body2" sx={{ mt: 1 }}>
                        {app.app_description}
                      </Typography>
                    </Box>

                    {isProjectLead && (
                      <IconButton>
                        <EditIcon />
                      </IconButton>
                    )}
                  </Stack>
                </CardContent>
              </Card>
            ))}
          </Stack>
        </Paper>
      </Container>
    </Box>
  );
}
