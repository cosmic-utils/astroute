# Package hooks must leave an active helper available for verified cleanup.
check_controls() {
    for state in /run/cosmic-netguard/*/active /run/cosmic-netguard/*/control.sock; do
        if [ -e "$state" ]; then
            echo 'Disable Astroute controls and quit before updating or removing this package.' >&2
            return 1
        fi
    done
    if command -v pgrep >/dev/null 2>&1 && { pgrep -x astroute >/dev/null || pgrep -x astroute-helper >/dev/null; }; then
        echo 'Quit Astroute before updating or removing this package.' >&2
        return 1
    fi
    return 0
}
