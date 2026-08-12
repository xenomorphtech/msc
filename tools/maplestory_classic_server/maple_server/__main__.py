import sys


if sys.argv[1:2] == ["live-proxy"]:
    from .live_proxy import main

    main(sys.argv[2:])
else:
    from .server import main

    main()
