import sys

# pm relies on Linux-only calls (SO_PEERCRED, prctl, the resource module); on any other platform it stops here,
# before a module that uses them is imported, instead of failing halfway with a traceback
if not sys.platform.startswith("linux"):
    raise SystemExit("pm only supports Linux.")
