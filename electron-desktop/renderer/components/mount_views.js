(function mountRegisteredViews() {
    'use strict';
    const root = document.getElementById('workspace-views');
    window.WSHawkViewRegistry.mount(root);
})();
