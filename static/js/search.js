document.addEventListener('DOMContentLoaded', function() {
    // Função para obter o valor da célula para ordenação
    const getCellValue = (tr, idx) => {
        const cell = tr.children[idx];
        if (idx === 8) { // Coluna Status
            return cell.querySelector('.status').textContent.trim();
        }
        if (idx === 2) { // Coluna SO
            return cell.querySelector('strong').textContent.trim().toLowerCase();
        }
        if (idx === 9) { // Coluna Última Atividade
            const dateText = cell.textContent.trim();
            if (!dateText) return 0;

            try {
                const [datePart, timePart] = dateText.split(' ');
                const [day, month, year] = datePart.split('/').map(Number);
                let hours = 0, minutes = 0;

                if (timePart) {
                    [hours, minutes] = timePart.split(':').map(Number);
                }

                const dateObj = new Date(year, month - 1, day, hours, minutes);
                return dateObj.getTime();
            } catch (e) {
                console.error('Erro ao converter data:', dateText, e);
                return 0;
            }
        }
        return cell.textContent.trim().toLowerCase();
    };

    // Função comparadora para ordenação
    const comparer = (idx, asc) => (a, b) => {
        const valA = getCellValue(asc ? a : b, idx);
        const valB = getCellValue(asc ? b : a, idx);

        if (!isNaN(valA) && !isNaN(valB)) {
            return valA - valB;
        }

        if (idx === 8) {
            const statusOrder = { 'Ativo': 1, 'Inativo': 0 };
            return statusOrder[valA] - statusOrder[valB];
        }

        return valA.localeCompare(valB, 'pt', { sensitivity: 'base' });
    };

    // Adicionar eventos de clique nos cabeçalhos
    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const tbody = table.querySelector('tbody');
            const columnIndex = Array.from(th.parentNode.children).indexOf(th);
            const isAsc = th.classList.contains('asc');

            // Remover classes de ordenação de todos os cabeçalhos
            table.querySelectorAll('th').forEach(header => {
                header.classList.remove('asc', 'desc');
            });

            // Definir nova direção
            const newDir = !isAsc;
            th.classList.toggle('asc', newDir);
            th.classList.toggle('desc', !newDir);

            // Ordenar as linhas
            Array.from(tbody.querySelectorAll('tr'))
                .sort(comparer(columnIndex, newDir))
                .forEach(tr => tbody.appendChild(tr));
        });
    });
});