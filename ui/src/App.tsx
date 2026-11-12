import { useRoute } from './lib/route';
import { Shell } from './ui/Shell';
import { History } from './screens/History';
import { Inventory } from './screens/Inventory';
import { NotFound } from './screens/NotFound';
import { Todo } from './screens/Todo';
import { Trust } from './screens/Trust';

export function App() {
  const route = useRoute();
  let screen;
  switch (route.name) {
    case 'inventory':
      screen = <Inventory view={route.view} object={route.object} />;
      break;
    case 'history':
      screen = <History id={route.id} />;
      break;
    case 'trust':
      screen = <Trust />;
      break;
    case 'notfound':
      screen = <NotFound hash={route.hash} />;
      break;
    default:
      screen = <Todo tab={route.tab} />;
  }
  return <Shell route={route}>{screen}</Shell>;
}
