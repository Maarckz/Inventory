
document.addEventListener('DOMContentLoaded', function() {
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    if (!themeToggleBtn) return;

    const themeIconSun = themeToggleBtn.querySelector('.fa-sun');
    const themeIconMoon = themeToggleBtn.querySelector('.fa-moon');

    const root = document.documentElement;

    function updateIcons(dark) {
        themeIconSun.style.opacity = dark ? '0' : '1';
        themeIconSun.style.transform = dark ? 'rotate(-90deg)' : 'rotate(0deg)';
        themeIconMoon.style.opacity = dark ? '1' : '0';
        themeIconMoon.style.transform = dark ? 'rotate(0deg)' : 'rotate(90deg)';
    }

    themeToggleBtn.addEventListener('click', function() {

        root.classList.add('no-transition');
        document.body.classList.add('no-transition');

        const isDark = !root.classList.contains('dark-mode');
        root.classList.toggle('dark-mode', isDark);
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        updateIcons(isDark);

        setTimeout(() => {
            root.classList.remove('no-transition');
            document.body.classList.remove('no-transition');
        }, 300);
    });

    updateIcons(root.classList.contains('dark-mode'));

});
