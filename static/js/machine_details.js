document.addEventListener('DOMContentLoaded', function() {

    function toggleSection(header) {
        const section = header.parentElement;
        const body = section.querySelector('.section-body');
        const icon = section.querySelector('.toggle-icon');
        if (!body) return;

        const nowCollapsed = section.classList.toggle('collapsed');

        if (nowCollapsed) {
            body.style.display = 'none';
            if (icon) { icon.classList.remove('fa-chevron-down'); icon.classList.add('fa-chevron-right'); }
        } else {
            body.style.display = 'block';
            body.classList.remove('section-anim');
            void body.offsetWidth;
            body.classList.add('section-anim');
            if (icon) { icon.classList.remove('fa-chevron-right'); icon.classList.add('fa-chevron-down'); }
        }
    }

    function sortTable(table, columnIndex, sortType) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const header = table.querySelectorAll('th')[columnIndex];
        const isAscending = !header.classList.contains('asc');

        table.querySelectorAll('th').forEach(th => {
            th.classList.remove('asc', 'desc');
        });

        header.classList.add(isAscending ? 'asc' : 'desc');

        rows.sort((a, b) => {
            const aValue = a.children[columnIndex].textContent;
            const bValue = b.children[columnIndex].textContent;

            if (sortType === 'number') {
                const numA = parseFloat(aValue) || 0;
                const numB = parseFloat(bValue) || 0;
                return isAscending ? numA - numB : numB - numA;
            } else {
                return isAscending ?
                    aValue.localeCompare(bValue) :
                    bValue.localeCompare(aValue);
            }
        });

        rows.forEach(row => tbody.removeChild(row));
        rows.forEach(row => tbody.appendChild(row));
    }

    document.querySelectorAll('.sortable th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const columnIndex = Array.from(th.parentElement.children).indexOf(th);
            const sortType = th.getAttribute('data-sort');
            sortTable(table, columnIndex, sortType);
        });
    });

    window.toggleSection = toggleSection;

    document.querySelectorAll('.section-header').forEach(header => {
        header.classList.add('clickable');
        header.addEventListener('click', (e) => {
            if (e.target.closest('button, a, th, input, select, .sortable')) return;
            toggleSection(header);
        });
    });

    const portTable = document.querySelector('.port-table');
    if (portTable) {
        sortTable(portTable, 0, 'number');
    }
});
