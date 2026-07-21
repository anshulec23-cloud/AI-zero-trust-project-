"""
Aegis ICS Desktop Application — Main Launcher
===============================================
Entry point for the Aegis ICS desktop application.
Starts Flask backend on a random ephemeral port, launches the PyWebView
embedded browser window, system tray icon, and auto-update checker.

Usage:
    python launcher.py          (development mode)
    AegisICS.exe                (frozen PyInstaller build)

Copyright (c) 2024–2026 Aegis ICS Project. All rights reserved.
"""

import os 
import sys 
import logging 
import threading 
from werkzeug .serving import make_server 




logging .basicConfig (
level =logging .INFO ,
format ="[%(asctime)s] %(name)s %(levelname)s: %(message)s",
datefmt ="%H:%M:%S",
)
logger =logging .getLogger ("aegis.launcher")




os .environ ["AEGIS_DESKTOP_MODE"]="1"


def _configure_paths ():
    """Ensure frozen PyInstaller paths resolve correctly."""
    if hasattr (sys ,"_MEIPASS"):

        os .chdir (sys ._MEIPASS )
        logger .info ("Running in frozen mode — base: %s",sys ._MEIPASS )
    else :

        source_dir =os .path .dirname (os .path .abspath (__file__ ))
        os .chdir (source_dir )
        logger .info ("Running in development mode — base: %s",source_dir )


def _create_flask_server (port :int ):
    """
    Create and return a Werkzeug WSGI server bound to 127.0.0.1:<port>.

    This avoids the race condition that exists with Flask's app.run()
    by binding the socket immediately and atomically.
    """

    from app import app 


    app .config ["DEBUG"]=False 
    app .config ["TESTING"]=False 

    server =make_server ("127.0.0.1",port ,app ,threaded =True )
    actual_port =server .socket .getsockname ()[1 ]
    logger .info ("Flask server bound to 127.0.0.1:%d",actual_port )
    return server ,actual_port 




def _start_update_check (window ):
    """Run background update check and notify the UI if an update exists."""
    try :
        from security import APP_VERSION ,GITHUB_REPO 
        from updater import check_for_updates 

        info =check_for_updates (APP_VERSION ,GITHUB_REPO )
        if info .available and window is not None :
            js_code =(
            f"if (typeof showUpdateBanner === 'function') {{"
            f"  showUpdateBanner('{info .latest_version }', '{info .download_url }');"
            f"}}"
            )
            try :
                window .evaluate_js (js_code )
                logger .info (
                "Update available: v%s -> v%s",
                info .current_version ,
                info .latest_version ,
                )
            except Exception :
                logger .debug ("Could not inject update banner (window may not be ready)")
        elif not info .available :
            logger .info ("Software is up to date (v%s)",APP_VERSION )
    except Exception as exc :
        logger .warning ("Update check failed (non-critical): %s",exc )


def _on_window_closing ():
    """
    Called when the user clicks the window's X button.
    Hides the window to the system tray instead of quitting.
    """
    global _webview_window 
    if _webview_window is not None :
        try :
            _webview_window .hide ()
        except Exception :
            pass 
    return False 


def _on_quit ():
    """Called from the system tray's Quit action. Shuts everything down."""
    global _webview_window ,_flask_server ,_tray 
    logger .info ("Shutdown requested — stopping all services...")

    if _tray is not None :
        try :
            _tray .stop ()
        except Exception :
            pass 

    if _flask_server is not None :
        try :
            _flask_server .shutdown ()
        except Exception :
            pass 

    if _webview_window is not None :
        try :
            _webview_window .destroy ()
        except Exception :
            pass 

    logger .info ("All services stopped. Goodbye.")


def _on_check_updates_from_tray ():
    """Triggered from tray menu → Check for Updates."""
    global _webview_window 
    threading .Thread (
    target =_start_update_check ,
    args =(_webview_window ,),
    daemon =True ,
    name ="tray-update-check",
    ).start ()





_webview_window =None 
_flask_server =None 
_tray =None 


def main ():
    """
    Main entry point for the Aegis ICS desktop application.

    Orchestration order:
        1. Configure paths
        2. Find a free port
        3. Start Flask WSGI server (daemon thread)
        4. Start system tray (daemon thread)
        5. Start update checker (daemon thread)
        6. Create PyWebView window (MAIN THREAD — required by Windows)
    """
    global _webview_window ,_flask_server ,_tray 

    _configure_paths ()


    try :
        from security import check_debugger 
        if check_debugger ():
            logger .critical ("Debugger detected — refusing to start.")
            sys .exit (1 )
    except Exception :
        pass 


    from security import find_free_port 
    port =find_free_port ()
    logger .info ("Selected ephemeral port: %d",port )


    _flask_server ,actual_port =_create_flask_server (port )
    os .environ ["FLASK_PORT"]=str (actual_port )

    flask_thread =threading .Thread (
    target =_flask_server .serve_forever ,
    daemon =True ,
    name ="flask-backend",
    )
    flask_thread .start ()
    logger .info ("Flask backend started on thread '%s'",flask_thread .name )




    try :
        import webview 
    except ImportError :
        logger .critical (
        "pywebview is not installed. Install it with: pip install pywebview"
        )
        sys .exit (1 )


    _webview_window =webview .create_window (
    title ="Aegis ICS — Industrial Control System Security",
    url =f"http://127.0.0.1:{actual_port }",
    width =1366 ,
    height =800 ,
    resizable =True ,
    min_size =(1024 ,600 ),
    text_select =False ,
    zoomable =False ,
    )


    _webview_window .events .closing +=_on_window_closing 


    try :
        from tray import AegisTray 

        _tray =AegisTray (
        window =_webview_window ,
        on_quit_callback =_on_quit ,
        on_check_updates =_on_check_updates_from_tray ,
        )
        tray_thread =threading .Thread (
        target =_tray .run ,
        daemon =True ,
        name ="system-tray",
        )
        tray_thread .start ()
        logger .info ("System tray started on thread '%s'",tray_thread .name )
    except ImportError :
        logger .warning ("pystray not installed — system tray disabled.")
    except Exception as exc :
        logger .warning ("System tray failed to start: %s",exc )


    update_thread =threading .Thread (
    target =_start_update_check ,
    args =(_webview_window ,),
    daemon =True ,
    name ="update-checker",
    )
    update_thread .start ()


    logger .info ("Starting PyWebView event loop...")
    webview .start (debug =False )


    logger .info ("Aegis ICS Edge is shutting down... Cleaning up background threads.")


    try :
        import serial_gateway 
        serial_gateway .stop_gateway ()
    except Exception as e :
        logger .error (f"Error stopping gateway: {e }")

    import time 
    time .sleep (0.5 )


    os ._exit (0 )


if __name__ =="__main__":
    main ()
