#!/bin/bash
exec /opt/homebrew/bin/cloudflared --config /Users/stevenpetteruti/.cloudflared/config.yml tunnel run cbstress
