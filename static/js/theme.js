// static/js/theme.js - Versão atualizada
document.addEventListener('DOMContentLoaded', function() {
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const themeIconSun = themeToggleBtn.querySelector('.fa-sun');
    const themeIconMoon = themeToggleBtn.querySelector('.fa-moon');
    
    // Verificar tema salvo no localStorage
    const savedTheme = localStorage.getItem('theme') || 'light';
    
    // Aplicar tema salvo (já aplicado via inline script, mas garantindo)
    if (savedTheme === 'dark' && !document.body.classList.contains('dark-mode')) {
        document.body.classList.add('dark-mode');
    }
    
    // Alternar tema
    themeToggleBtn.addEventListener('click', function() {
        // Desativar transições durante a mudança
        document.body.classList.add('no-transition');
        
        // Alternar tema
        document.body.classList.toggle('dark-mode');
        
        const isDarkMode = document.body.classList.contains('dark-mode');
        
        // Salvar preferência no localStorage
        localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
        
        // Atualizar ícones
        if (isDarkMode) {
            themeIconSun.style.opacity = '0';
            themeIconSun.style.transform = 'rotate(-90deg)';
            themeIconMoon.style.opacity = '1';
            themeIconMoon.style.transform = 'rotate(0deg)';
        } else {
            themeIconSun.style.opacity = '1';
            themeIconSun.style.transform = 'rotate(0deg)';
            themeIconMoon.style.opacity = '0';
            themeIconMoon.style.transform = 'rotate(90deg)';
        }
        
        // Reativar transições após um breve delay
        setTimeout(() => {
            document.body.classList.remove('no-transition');
        }, 300);
    });
    
    // Inicializar estado dos ícones
    if (savedTheme === 'dark') {
        themeIconSun.style.opacity = '0';
        themeIconSun.style.transform = 'rotate(-90deg)';
        themeIconMoon.style.opacity = '1';
        themeIconMoon.style.transform = 'rotate(0deg)';
    }
});