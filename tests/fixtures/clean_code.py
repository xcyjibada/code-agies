"""A clean module with no vulnerabilities."""

from datetime import datetime


def format_date(year, month, day):
    d = datetime(year, month, day)
    return d.strftime("%Y-%m-%d")


def greeting():
    return "Hello, world!"
