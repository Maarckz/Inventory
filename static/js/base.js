document.addEventListener('DOMContentLoaded', function() {
    // Fechar alertas
    document.querySelectorAll('.alert-close').forEach(button => {
        button.addEventListener('click', function() {
            this.parentElement.remove();
        });
    });

    // Animar linhas da tabela de pesquisa
    const tableRows = document.querySelectorAll('.machine-table tbody tr');
    tableRows.forEach((row, i) => {
        row.style.animationDelay = (i * 0.07) + 's';
    });

    // Tornar linhas da tabela clicáveis
    document.querySelectorAll('.machine-row').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function() {
            window.location.href = this.getAttribute('data-href');
        });
    });
});