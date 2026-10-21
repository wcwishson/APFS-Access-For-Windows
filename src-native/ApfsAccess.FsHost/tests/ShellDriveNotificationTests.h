#pragma once

bool TestShellDriveNotificationsDoNotWaitForExplorer()
{
    struct Event { HWND target; UINT message; WPARAM event; LPARAM data; };
    std::vector<Event> events;
    auto prior_hook = std::move(g_shell_drive_refresh_test_hook);
    ScopeExit restore{[&] { g_shell_drive_refresh_test_hook = std::move(prior_hook); }};
    bool accepted = true;
    g_shell_drive_refresh_test_hook = [&](HWND target, UINT message, WPARAM event, LPARAM data) {
        events.push_back({target, message, event, data});
        return accepted ? TRUE : FALSE;
    };
    bool ok = true;
    for (const bool added : {true, false})
    {
        for (const auto* mount : {L"e:", L"q:\\", L"q:/"})
        {
            events.clear();
            if (added) NotifyShellDriveAdded(mount); else NotifyShellDriveRemoved(mount);
            const std::wstring root = std::wstring(1, mount[0] == L'e' ? L'E' : L'Q') + L":\\";
            ok &= Require(ShellNotificationDriveRoot(mount) == root, "Shell refresh: exact drive-root classification");
            ok &= Require(events.size() == 1, "Shell refresh: one queued topology update per lifecycle event");
            for (std::size_t i = 0; i < events.size(); ++i)
            {
                const auto& event = events[i];
                ok &= Require(event.target == HWND_BROADCAST && event.message == WM_DEVICECHANGE &&
                        event.event == DBT_DEVNODES_CHANGED && event.data == 0,
                    "Shell refresh: asynchronous system message has no path or pointer requiring provider I/O");
            }
        }
    }
    for (const auto* mount : {L"", L"1:", L"EE:", L"E:\\folder", L"D:\\ApfsAccessScratch\\PrivateMounts\\test"})
    {
        events.clear();
        NotifyShellDriveAdded(mount);
        NotifyShellDriveRemoved(mount);
        ok &= Require(events.empty(), "Shell notification: directory and invalid mounts emit no global event");
    }
    accepted = false;
    events.clear();
    NotifyShellDriveAdded(L"E:");
    NotifyShellDriveRemoved(L"E:");
    ok &= Require(events.size() == 2, "Shell refresh: a refused post performs no synchronous fallback or retry");
    return ok;
}
