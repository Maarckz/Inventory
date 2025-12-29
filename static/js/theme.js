document.addEventListener('DOMContentLoaded', function() {
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const themeIconSun = themeToggleBtn.querySelector('.fa-sun');
    const themeIconMoon = themeToggleBtn.querySelector('.fa-moon');
    
    const savedTheme = localStorage.getItem('theme') || 'light';
    
    if (savedTheme === 'dark' && !document.body.classList.contains('dark-mode')) {
        document.body.classList.add('dark-mode');
    }
    
    themeToggleBtn.addEventListener('click', function() {
        document.body.classList.add('no-transition');
        
        document.body.classList.toggle('dark-mode');
        
        const isDarkMode = document.body.classList.contains('dark-mode');
        
        localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
        
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
        
        setTimeout(() => {
            document.body.classList.remove('no-transition');
        }, 300);
    });
    
    if (savedTheme === 'dark') {
        themeIconSun.style.opacity = '0';
        themeIconSun.style.transform = 'rotate(-90deg)';
        themeIconMoon.style.opacity = '1';
        themeIconMoon.style.transform = 'rotate(0deg)';
    }
});