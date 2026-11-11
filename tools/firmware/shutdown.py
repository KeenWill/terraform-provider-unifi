"""Turn service termination into normal exception cleanup for disposable VMs."""
import signal


class ShutdownRequested(InterruptedError):
    """A service stop must escape ordinary per-target failure handling."""


def install_shutdown_handler():
    def terminate(_signum, _frame):
        # Ignore repeated TERM while finally blocks terminate children and
        # remove their overlays. The service manager retains its hard timeout.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise ShutdownRequested("firmware job terminated")
    signal.signal(signal.SIGTERM, terminate)
