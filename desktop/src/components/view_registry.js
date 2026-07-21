(function createViewRegistry(global) {
    'use strict';

    const components = [];
    const forbiddenMarkup = /<script\b|\son[a-z]+\s*=/i;

    function register(name, markup) {
        if (!name || typeof markup !== 'string' || !markup.trim()) {
            throw new TypeError('A named static view template is required');
        }
        if (forbiddenMarkup.test(markup)) {
            throw new Error(`Unsafe markup in static view component: ${name}`);
        }
        components.push({ name, markup });
    }

    function mount(root) {
        if (!(root instanceof Element)) {
            throw new TypeError('A valid view mount element is required');
        }
        for (const component of components) {
            const template = document.createElement('template');
            // Templates are local, compile-time assets validated above. Runtime data
            // must continue to use textContent/createElement in renderer modules.
            template.innerHTML = component.markup;
            root.appendChild(template.content.cloneNode(true));
        }
        root.dataset.componentsMounted = String(components.length);
    }

    global.WSHawkViewRegistry = Object.freeze({ register, mount });
})(window);
