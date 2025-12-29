document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.alert-close').forEach(button => {
        button.addEventListener('click', function() {
            this.parentElement.remove();
        });
    });

    const tableRows = document.querySelectorAll('.machine-table tbody tr');
    tableRows.forEach((row, i) => {
        row.style.animationDelay = (i * 0.07) + 's';
    });

    document.querySelectorAll('.machine-row').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function() {
            window.location.href = this.getAttribute('data-href');
        });
    });
});