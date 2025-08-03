/**
 * Common utility functions used across the application
 */

// Toggle section visibility
function toggleSection(sectionHeader) {
    const section = sectionHeader.parentElement;
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

// Sort table by column
function sortTable(table, columnIndex, sortType) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const header = table.querySelectorAll('th')[columnIndex];
    const isAscending = !header.classList.contains('asc');

    // Remove sorting classes from all headers
    table.querySelectorAll('th').forEach(th => {
        th.classList.remove('asc', 'desc');
    });

    // Add class to current header
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

    // Remove all rows
    rows.forEach(row => tbody.removeChild(row));
    
    // Add sorted rows
    rows.forEach(row => tbody.appendChild(row));
}

// Initialize table sorting
function initTableSorting() {
    document.querySelectorAll('.sortable th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const columnIndex = Array.from(th.parentElement.children).indexOf(th);
            const sortType = th.getAttribute('data-sort');
            sortTable(table, columnIndex, sortType);
        });
    });
}

// Initialize section toggles
function initSectionToggles() {
    document.querySelectorAll('.section-header').forEach(header => {
        header.addEventListener('click', (e) => {
            if (e.target.tagName !== 'TH' && !e.target.classList.contains('section-header')) {
                toggleSection(header);
            }
        });
    });
}

// Initialize row click events
function initRowClickEvents() {
    document.querySelectorAll('[data-href]').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function() {
            window.location.href = this.getAttribute('data-href');
        });
    });
}

// Document ready handler
document.addEventListener('DOMContentLoaded', function() {
    initTableSorting();
    initSectionToggles();
    initRowClickEvents();
    
    // Initialize any tables that should be sorted by default
    const portTable = document.querySelector('.port-table');
    if (portTable) {
        sortTable(portTable, 0, 'number');
    }
    
    // Animate table rows
    const rows = document.querySelectorAll('.machine-table tbody tr');
    rows.forEach((row, i) => {
        row.style.animationDelay = (i * 0.07) + 's';
    });
});