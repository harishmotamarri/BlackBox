document.addEventListener('DOMContentLoaded', () => {
    // Desktop Dropdowns
    const dropdowns = document.querySelectorAll('.dropdown');

    dropdowns.forEach(dropdown => {
        const btn = dropdown.querySelector('.dropdown-btn');
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                dropdown.classList.toggle('active');
            });
        }
    });

    // Mobile Hamburger Menu Toggle
    const toggleBtn = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');

    if (toggleBtn && navMenu) {
        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleBtn.classList.toggle('active');
            navMenu.classList.toggle('active');
            
            // Adjust aria attributes
            const expanded = toggleBtn.classList.contains('active');
            toggleBtn.setAttribute('aria-expanded', expanded);
        });

        // Close menu when clicking links or buttons inside it
        navMenu.querySelectorAll('a, button').forEach(item => {
            item.addEventListener('click', () => {
                toggleBtn.classList.remove('active');
                navMenu.classList.remove('active');
                toggleBtn.setAttribute('aria-expanded', 'false');
            });
        });
    }

    // Close dropdowns and mobile menu when clicking outside
    document.addEventListener('click', (e) => {
        dropdowns.forEach(dropdown => {
            dropdown.classList.remove('active');
        });
        if (toggleBtn && navMenu && !navMenu.contains(e.target) && !toggleBtn.contains(e.target)) {
            toggleBtn.classList.remove('active');
            navMenu.classList.remove('active');
            toggleBtn.setAttribute('aria-expanded', 'false');
        }
    });
});
