    def _setup_eventloop(self):
        """Sets up a new eventloop as the current one according to the OS."""
        if os.name == "nt":
##            current_eventloop = asyncio.get_event_loop_policy().get_event_loop()
##            if isinstance(current_eventloop, asyncio.ProactorEventLoop):
##                self.eventloop = current_eventloop
##            else:
            # On Python before 3.8, Proactor is not the default eventloop type, so we have to create a new one.
            # If there was an existing eventloop this can create issues, since we effectively disable it here.
##            if asyncio.all_tasks():
##                warnings.warn("The running eventloop has tasks but pyshark must set a new eventloop to continue. "
##                              "Existing tasks may not run.")
            self.eventloop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(self.eventloop)
        else:
            try:
                self.eventloop = asyncio.get_event_loop_policy().get_event_loop()
            except RuntimeError:
                if threading.current_thread() != threading.main_thread():
                    # Ran not in main thread, make a new eventloop
                    self.eventloop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self.eventloop)
                else:
                    raise
            if os.name == "posix" and isinstance(threading.current_thread(), threading._MainThread):
                # The default child watchers (ThreadedChildWatcher) attach_loop method is empty!
                # While using pyshark with ThreadedChildWatcher, asyncio could raise a ChildProcessError
                # "Unknown child process pid %d, will report returncode 255"
                # This led to a TSharkCrashException in _cleanup_subprocess.
                # Using the SafeChildWatcher fixes this issue, but it is slower.
                # SafeChildWatcher O(n) -> large numbers of processes are slow
                # ThreadedChildWatcher O(1) -> independent of process number
                # asyncio.get_child_watcher().attach_loop(self.eventloop)
                asyncio.set_child_watcher(asyncio.SafeChildWatcher())
                asyncio.get_child_watcher().attach_loop(self.eventloop)
