"""
Aegis ICS — System Tray Integration Module

Provides system tray icon and menu for the Aegis ICS desktop application
on Windows. Handles tray icon creation, menu actions, and window
show/restore operations via pystray and Pillow.
"""

import os 
import sys 
import logging 
from typing import Any ,Callable ,Optional 

import pystray 
from PIL import Image ,ImageDraw 

logger =logging .getLogger (__name__ )


def _resource_path (relative_path :str )->str :
    """Resolve a resource path, compatible with PyInstaller bundles.

    When the application is bundled with PyInstaller, resources are
    extracted to a temporary directory referenced by ``sys._MEIPASS``.
    In development mode the path is resolved relative to this module's
    directory.

    Args:
        relative_path: The relative path to the resource file.

    Returns:
        Absolute path to the resource.
    """
    if hasattr (sys ,"_MEIPASS"):
        return os .path .join (sys ._MEIPASS ,relative_path )
    return os .path .join (os .path .dirname (os .path .abspath (__file__ )),relative_path )


def create_default_icon ()->Image .Image :
    """Create a simple fallback 64×64 tray icon using Pillow.

    Draws a filled green circle (#34d399) centred on a dark
    background (#1a1a1a).  Used when ``static/icon.png`` is not
    available on disk.

    Returns:
        A 64×64 RGBA :class:`PIL.Image.Image` suitable for use as a
        system-tray icon.
    """
    size =64 
    image =Image .new ("RGBA",(size ,size ),"#1a1a1a")
    draw =ImageDraw .Draw (image )
    padding =8 
    draw .ellipse (
    [padding ,padding ,size -padding ,size -padding ],
    fill ="#34d399",
    )
    return image 


class AegisTray :
    """System-tray icon and menu for the Aegis ICS application.

    The tray icon provides quick access to the main dashboard, an
    update-check action, and a quit option.  A left-click on the icon
    opens the dashboard (the *Open Dashboard* item is marked as the
    default action).

    Args:
        window: The pywebview window object (may be ``None`` during
            early initialisation).
        on_quit_callback: Callable invoked when the user selects
            *Quit Aegis ICS* from the tray menu.
        on_check_updates: Callable invoked when the user selects
            *Check for Updates* from the tray menu.
    """

    def __init__ (
    self ,
    window :Any ,
    on_quit_callback :Callable [[],None ],
    on_check_updates :Callable [[],None ],
    )->None :
        self .window :Any =window 
        self ._on_quit_callback :Callable [[],None ]=on_quit_callback 
        self ._on_check_updates :Callable [[],None ]=on_check_updates 

        icon_image =self ._load_icon ()

        menu =pystray .Menu (
        pystray .MenuItem (
        "Open Dashboard",
        self ._show_window ,
        default =True ,
        ),
        pystray .Menu .SEPARATOR ,
        pystray .MenuItem (
        "Check for Updates",
        self ._check_updates ,
        ),
        pystray .Menu .SEPARATOR ,
        pystray .MenuItem (
        "Quit Aegis ICS",
        self ._quit ,
        ),
        )

        self .icon :pystray .Icon =pystray .Icon (
        name ="AegisICS",
        icon =icon_image ,
        title ="Aegis ICS — Industrial Security v2.2.2",
        menu =menu ,
        )

        logger .info ("AegisTray initialised.")





    @staticmethod 
    def _load_icon ()->Image .Image :
        """Load the tray icon from disk, falling back to a generated one."""
        icon_path =_resource_path (os .path .join ("static","icon.png"))
        if os .path .isfile (icon_path ):
            logger .debug ("Loading tray icon from %s",icon_path )
            return Image .open (icon_path )
        logger .warning (
        "Icon file not found at %s; using generated fallback icon.",
        icon_path ,
        )
        return create_default_icon ()





    def _show_window (self ,icon :pystray .Icon ,item :pystray .MenuItem )->None :
        """Show and restore the pywebview window.

        Safely handles the case where ``self.window`` is ``None`` (e.g.
        if the window has not been created yet).
        """
        if self .window is None :
            logger .warning ("Cannot show window: window reference is None.")
            return 
        try :
            self .window .show ()
            self .window .restore ()
            logger .debug ("Window shown and restored.")
        except Exception :
            logger .exception ("Failed to show/restore the window.")

    def _check_updates (self ,icon :pystray .Icon ,item :pystray .MenuItem )->None :
        """Invoke the update-check callback provided at construction."""
        logger .info ("Check for Updates requested from tray menu.")
        self ._on_check_updates ()

    def _quit (self ,icon :pystray .Icon ,item :pystray .MenuItem )->None :
        """Stop the tray icon and invoke the quit callback."""
        logger .info ("Quit requested from tray menu.")
        self .icon .stop ()
        self ._on_quit_callback ()





    def run (self )->None :
        """Start the tray icon event loop (**blocking**).

        This method blocks the calling thread.  It should typically be
        launched inside a daemon thread so that the main thread remains
        free for the pywebview event loop.
        """
        logger .info ("Starting tray icon event loop.")
        self .icon .run ()

    def stop (self )->None :
        """Stop the tray icon gracefully."""
        logger .info ("Stopping tray icon.")
        self .icon .stop ()
