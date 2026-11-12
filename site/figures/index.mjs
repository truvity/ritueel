// The registry of the figures: the name a page gives <Figure name="..."/> and the module that draws it.
// site/test/figures.test.mjs checks every module and that every figure is placed on a page.
import signIntermediate from './sign-intermediate.mjs';
import ceremony from './ceremony.mjs';
import bindSubkeys from './bind-subkeys.mjs';
import threeLayers from './three-layers.mjs';
import rootCard from './root-card.mjs';
import dayToDayCard from './day-to-day-card.mjs';
import serverCard from './server-card.mjs';
import bundleFolder from './bundle-folder.mjs';
import usbStick from './usb-stick.mjs';
import insideAYubikey from './inside-a-yubikey.mjs';
import onePivSlot from './one-piv-slot.mjs';
import pivSignature from './piv-signature.mjs';
import twoKindsOfPasskey from './two-kinds-of-passkey.mjs';
import signIn from './sign-in.mjs';
import passkeyOpensKeyFile from './passkey-opens-key-file.mjs';
import twoBundlesOnePair from './two-bundles-one-pair.mjs';
import wholeChain from './whole-chain.mjs';
import threeStores from './three-stores.mjs';

const list = [signIntermediate, rootCard, dayToDayCard, serverCard, ceremony, bindSubkeys, threeLayers, bundleFolder, usbStick, insideAYubikey, onePivSlot, pivSignature, twoKindsOfPasskey, signIn, passkeyOpensKeyFile, twoBundlesOnePair, wholeChain, threeStores];

export const figures = Object.fromEntries(list.map((fig) => [fig.id, fig]));
