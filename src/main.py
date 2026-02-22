import sys

APP_VERSION = "1.0.0"

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        from cli import main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        main()
    else:
        from gui.app import run_app
        run_app()

