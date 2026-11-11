"""Turn service termination into normal exception cleanup for disposable VMs."""
import signal


def install_shutdown_handler():
    def terminate(_signum, _frame):
        # Ignore repeated TERM while finally blocks terminate children and
        # remove their overlays. The service manager retains its hard timeout.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise InterruptedError("firmware job terminated")
    signal.signal(signal.SIGTERM, terminate)
