// Package bundle opens a bundle folder on a workstation and turns what it holds into what the checks need:
// the settings of ritueel.yaml, the roots of the newest trust set, one request, and the configuration of the
// hand-off checks of package handoff. It also makes a new bundle folder with its starter wanted files
// ([Create], for the command new).
//
// Every read and every write of the bundle goes through package fsx: no path of the bundle is opened by
// the os package, and no link is followed in any element of a path. The package reads only what a command
// asks for: Open reads ritueel.yaml, a delegation is read when a checker for it is made, a request when it
// is asked for, and the trust folder when the roots are. The wanted files are read by package wanted, which
// is strict about them; a Settings, a Delegation or a Root that was not made by that package is refused.
//
// Nothing here writes into an existing bundle. [Create] makes a new folder and writes into it, and it
// stops at the first error, says what it already wrote, deletes nothing and does not retry.
package bundle
