const helpers = require("./helpers");
const { setupPageRoute } = helpers;

const app = express();

helpers.setupPageRoute(app, "/profile", [requireAuth], getProfile);
helpers.setupAdminPageRoute(app, "/admin", [requireAdmin], getAdmin);
helpers.setupApiRoute(app, "post", "/api/write", [requirePermission], writeApi);
setupPageRoute(app, "/direct", [requireAuth], getProfile);
