# About

This is a simple web application to analyse Dansguardian log files.

There are three tabs, Summary, Denied requests and Realtime log which all displays parsed data from the current day.

A PHP enabled web server is required to run this application.


# Screenshots

![](/dunse/dla/raw/master/screenshots/dla-summary.jpg)

![](/dunse/dla/raw/master/screenshots/dla-denied.jpg)

![](/dunse/dla/raw/master/screenshots/dla-realtime.jpg)


# Installation

Download the package from "Downloads" section.

Copy dla/ directory to your web/proxy server running Dansguardian. (E.g. to /var/www/dla/)

Access it through: http://your.web.server/dla/


# Notes

Make sure "logfileformat = 1" is set in dansguardian.conf

If "loglocation" is change from default, update getDansguardianLog.php with the correct path.