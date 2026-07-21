(function createSafeDomHelpers(global) {
    'use strict';

    function clear(node) {
        node?.replaceChildren();
    }

    function element(tagName, options = {}, children = []) {
        const node = document.createElement(tagName);
        if (options.className) node.className = options.className;
        if (options.text !== undefined) node.textContent = String(options.text);
        if (options.title !== undefined) node.title = String(options.title);
        for (const [name, value] of Object.entries(options.dataset || {})) {
            node.dataset[name] = String(value);
        }
        for (const child of children) {
            if (child) node.appendChild(child);
        }
        return node;
    }

    function emptyState(container, message) {
        container?.replaceChildren(element('div', { className: 'empty-state', text: message }));
    }

    function emptyTable(tbody, message, colSpan = 1) {
        const cell = element('td', { text: message });
        cell.colSpan = colSpan;
        tbody?.replaceChildren(element('tr', { className: 'empty-tr' }, [cell]));
    }

    function badge(className, text, title = '') {
        return element('span', { className, text, title });
    }

    global.WSHawkDOM = Object.freeze({ clear, element, emptyState, emptyTable, badge });
})(window);
