// Package bundle opens a bundle folder on a workstation and turns what it holds into what the checks need:
// the settings of ritueel.yaml, the roots and the OpenPGP primaries of the newest trust set, one request, and
// the configuration of the hand-off checks of package handoff. It also makes a new bundle folder with its
// starter wanted files ([Create], for the command new).
//
// Every read and every write of the bundle goes through package fsx: no path of the bundle is opened by
// the os package, and no link is followed in any element of a path. The package reads only what a command
// asks for: Open reads ritueel.yaml, a delegation is read when a checker for it is made, a request when it
// is asked for, and the trust folder when the roots are. The newest trust set is read once for a checker: its
// root list and CA bundle give the roots, and its keyring file, read by package openpgp with the entries of the
// root list, gives the primaries ([Bundle.Primaries]). The newest set is never replaced by an older one, and a
// keyring file that cannot be read or is refused stops the check: it never goes on with no primaries. Every fault
// of the primaries (a list that pins too many or gives one fingerprint to two entries, a missing keyring file, a
// refused one) is an error of the kind [ErrPrimaries]. The
// signature of the list and its expiry are not checked here. The wanted files are read by package wanted, which
// is strict about them; a Settings, a Delegation or a Root that was not made by that package is refused.
//
// Nothing here writes into an existing bundle. [Create] makes a new folder and writes into it, and it
// stops at the first error, says what it already wrote, deletes nothing and does not retry.
package bundle
