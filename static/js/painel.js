document.addEventListener('DOMContentLoaded', function() {
    // Mostrar/ocultar campo de pesquisa
    document.getElementById('show-search').addEventListener('click', function(e) {
        e.preventDefault();
        const panelHeader = this.parentElement;
        const searchContainer = document.getElementById('search-container');
        
        panelHeader.style.transition = 'opacity 0.2s';
        panelHeader.style.opacity = 0;
        panelHeader.style.pointerEvents = 'none';
        
        setTimeout(function() {
            panelHeader.style.display = 'none';
            searchContainer.style.display = 'block';
            setTimeout(function() {
                searchContainer.style.opacity = 1;
            }, 10);
        }, 400);
    });

    // Animar cards de máquinas
    const machineCards = document.querySelectorAll('.machine-card');
    machineCards.forEach((card, i) => {
        card.style.animationDelay = (0.1 * (i + 1)) + 's';
    });
});

