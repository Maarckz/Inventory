document.addEventListener('DOMContentLoaded', function() {
    // Função para alternar seções (expandir/retrair)
    function toggleSection(header) {
        const section = header.parentElement;
        const body = section.querySelector('.section-body');
        const icon = section.querySelector('.toggle-icon');
        
        if (body.style.display === 'none') {
            body.style.display = 'block';
            icon.classList.remove('fa-chevron-right');
            icon.classList.add('fa-chevron-down');
        } else {
            body.style.display = 'none';
            icon.classList.remove('fa-chevron-down');
            icon.classList.add('fa-chevron-right');
        }
    }

    // Função para ordenar tabelas
    function sortTable(table, columnIndex, sortType) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const header = table.querySelectorAll('th')[columnIndex];
        const isAscending = !header.classList.contains('asc');

        // Remover classes de ordenação de todos os cabeçalhos
        table.querySelectorAll('th').forEach(th => {
            th.classList.remove('asc', 'desc');
        });

        // Adicionar classe ao cabeçalho atual
        header.classList.add(isAscending ? 'asc' : 'desc');

        rows.sort((a, b) => {
            const aValue = a.children[columnIndex].textContent;
            const bValue = b.children[columnIndex].textContent;
            
            if (sortType === 'number') {
                const numA = parseFloat(aValue) || 0;
                const numB = parseFloat(bValue) || 0;
                return isAscending ? numA - numB : numB - numA;
            } else {
                return isAscending 
                    ? aValue.localeCompare(bValue) 
                    : bValue.localeCompare(aValue);
            }
        });

        // Remover todas as linhas
        rows.forEach(row => tbody.removeChild(row));
        
        // Adicionar linhas ordenadas
        rows.forEach(row => tbody.appendChild(row));
    }

    // Adicionar eventos de clique aos cabeçalhos das tabelas
    document.querySelectorAll('.sortable th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const columnIndex = Array.from(th.parentElement.children).indexOf(th);
            const sortType = th.getAttribute('data-sort');
            sortTable(table, columnIndex, sortType);
        });
    });

    // Adicionar eventos de clique aos cabeçalhos das seções
    document.querySelectorAll('.section-header').forEach(header => {
        header.addEventListener('click', (e) => {
            const target = e.target;
            if (target.tagName === 'TH' || target.classList.contains('section-header') || target.classList.contains('toggle-icon')) {
                toggleSection(header);
            }
        });
    });

    // Ordenar automaticamente a tabela de portas por número de porta (ordem crescente)
    const portTable = document.querySelector('.port-table');
    if (portTable) {
        sortTable(portTable, 0, 'number');
    }
});
