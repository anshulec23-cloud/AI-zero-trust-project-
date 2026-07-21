"""
GitHub Auto-Update Checker for Aegis ICS.

This module provides functionality to check for new releases of the
Aegis ICS desktop application on GitHub. It is designed to run as a
non-blocking background check during application startup.
"""

import logging 
import threading 
from dataclasses import dataclass ,field 
from typing import Callable 

import requests 

logger =logging .getLogger (__name__ )


@dataclass 
class UpdateInfo :
    """Information about an available application update.

    Attributes:
        available: Whether a newer version is available.
        current_version: The version currently running.
        latest_version: The latest version found on GitHub.
        download_url: URL to the release page for downloading.
        release_notes: Body/description of the latest release.
        published_at: ISO 8601 timestamp of when the release was published.
    """

    available :bool =False 
    current_version :str =""
    latest_version :str =""
    download_url :str =""
    release_notes :str =""
    published_at :str =""


def _parse_semver (version :str )->tuple [int ,...]:
    """Parse a version string into a tuple of integers for comparison.

    Args:
        version: A semver-style version string (e.g. '1.2.3').

    Returns:
        A tuple of integers representing the version components.
    """
    return tuple (int (part )for part in version .split ("."))


def check_for_updates (current_version :str ,repo :str )->UpdateInfo :
    """Check GitHub for a newer release of the application.

    Queries the GitHub public API for the latest release of the given
    repository and compares it against the current version using manual
    semver tuple comparison.

    This function is designed to **never crash**. Any exception encountered
    during the network request, JSON parsing, or version comparison is
    caught, logged, and results in an UpdateInfo with ``available=False``.

    Args:
        current_version: The currently running version string (e.g. '1.0.0').
        repo: The GitHub repository in 'owner/repo' format
              (e.g. 'aegis-ics/aegis-desktop').

    Returns:
        An UpdateInfo instance describing the update status.
    """
    try :
        url =f"https://api.github.com/repos/{repo }/releases/latest"
        response =requests .get (url ,timeout =5 )
        response .raise_for_status ()

        data =response .json ()

        tag_name :str =data .get ("tag_name","")
        html_url :str =data .get ("html_url","")
        body :str =data .get ("body","")or ""
        published_at :str =data .get ("published_at","")


        latest_version =tag_name .lstrip ("v")


        current_tuple =_parse_semver (current_version )
        latest_tuple =_parse_semver (latest_version )
        is_available =latest_tuple >current_tuple 

        logger .info (
        "Update check complete: current=%s, latest=%s, available=%s",
        current_version ,
        latest_version ,
        is_available ,
        )

        return UpdateInfo (
        available =is_available ,
        current_version =current_version ,
        latest_version =latest_version ,
        download_url =html_url ,
        release_notes =body ,
        published_at =published_at ,
        )

    except Exception :
        logger .error (
        "Failed to check for updates for repo '%s'",repo ,exc_info =True 
        )
        return UpdateInfo (
        available =False ,
        current_version =current_version ,
        )


def check_updates_async (
current_version :str ,repo :str ,callback :Callable [[UpdateInfo ],None ]
)->None :
    """Check for updates in a background thread without blocking the UI.

    Spawns a daemon thread that runs :func:`check_for_updates` and invokes
    the provided callback with the resulting :class:`UpdateInfo` once the
    check is complete.

    Args:
        current_version: The currently running version string (e.g. '1.0.0').
        repo: The GitHub repository in 'owner/repo' format.
        callback: A callable that receives the UpdateInfo result. This will
                  be called from the background thread.
    """

    def _worker ()->None :
        update_info =check_for_updates (current_version ,repo )
        callback (update_info )

    thread =threading .Thread (target =_worker ,name ="update-checker",daemon =True )
    thread .start ()
    logger .debug ("Background update check started for repo '%s'",repo )
