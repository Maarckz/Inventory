document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.alert-close').forEach(button => {
        button.addEventListener('click', function() {
            const alert = this.parentElement;
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(100px)';
            setTimeout(() => alert.remove(), 400);
        });
    });

    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            if (alert.parentElement) {
                alert.style.opacity = '0';
                alert.style.transform = 'translateX(100px)';
                setTimeout(() => alert.remove(), 400);
            }
        }, 5000);
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

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal.active').forEach(m => {
                m.classList.remove('active');
            });
        }
    });
});

function showToast(message, category = 'success') {
    const container = document.querySelector('.toast-container');
    if (!container) return;

    const alert = document.createElement('div');
    alert.className = `alert alert-${category} toast-show`;
    alert.innerHTML = `
        <span>${message}</span>
        <button class="alert-close">
            <i class="fas fa-times"></i>
        </button>
    `;

    container.appendChild(alert);

    alert.querySelector('.alert-close').addEventListener('click', () => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateX(100px)';
        setTimeout(() => alert.remove(), 400);
    });

    setTimeout(() => {
        if (alert.parentElement) {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(100px)';
            setTimeout(() => alert.remove(), 400);
        }
    }, 5000);
}