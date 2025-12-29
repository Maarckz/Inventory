document.addEventListener('DOMContentLoaded', function() {
    
    const searchBtn = document.getElementById('show-search');
    const panelHeader = document.querySelector('.panel-header');
    const searchContainer = document.getElementById('search-container');
    const searchInput = document.querySelector('input[name="query"]');

    if (searchBtn && panelHeader && searchContainer) {
        searchBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            panelHeader.classList.add('hidden');
            
            searchContainer.classList.add('open');
            
            setTimeout(() => {
                if (searchInput) searchInput.focus();
            }, 300); 
        });
    }

    const machineCards = document.querySelectorAll('.machine-card');
    
    machineCards.forEach((card, i) => {
        if (i < 20) {
            card.style.animationDelay = (0.05 * i) + 's';
        } else {
            card.style.animationDelay = '0s';
            card.style.opacity = '1'; 
        }
    });
});