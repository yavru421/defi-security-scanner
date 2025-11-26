# strict_mode.py
# Activates strict error handling for APT pipeline.
# Implements a fatal excepthook to ensure any uncaught exception is terminal.
import sys
import traceback
import os


def strict_excepthook(exc_type, exc_value, exc_tb):
	try:
		# Print the fatal error header
		print(f"\n❌ APT FATAL ERROR: {exc_type.__name__} – {exc_value}")
		# Print the full traceback
		traceback.print_exception(exc_type, exc_value, exc_tb)
	except Exception:
		# Ensure this function never raises
		pass
	# Exit with non-zero to indicate fatal error
	sys.exit(1)


# Install the fatal excepthook unless explicitly disabled via env
if not os.environ.get("AUA_ALLOW_NON_FATAL_EXCEPTIONS"):
	sys.excepthook = strict_excepthook
	print("⚙️ APT Fatal Mode Active: All exceptions are terminal.")

