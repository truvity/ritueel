// The registry of the figures: the name a page gives <Figure name="..."/> and the module that draws it.
// site/test/figures.test.mjs checks every module and that every figure is placed on a page.
import signIntermediate from './sign-intermediate.mjs';
import ceremony from './ceremony.mjs';
import bindSubkeys from './bind-subkeys.mjs';
import ideas from './ideas.mjs';
import rootCard from './root-card.mjs';
import dayToDayCard from './day-to-day-card.mjs';
import serverCard from './server-card.mjs';

const list = [signIntermediate, rootCard, dayToDayCard, serverCard, ceremony, bindSubkeys, ideas];

export const figures = Object.fromEntries(list.map((fig) => [fig.id, fig]));
