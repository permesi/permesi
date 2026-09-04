#!/usr/bin/env sh
set -eu

# Chezmoi runs hooks during dry runs too. Do not modify Git or SSH state when
# the user only asked to preview an apply.
case " ${CHEZMOI_ARGS:-} " in
*" --dry-run "* | *" -n "*) exit 0 ;;
esac

exec sh /workspaces/permesi/.devcontainer/configure-git.sh
