// Main JavaScript file for the HTML project

document.addEventListener('DOMContentLoaded', () => {
    // Initialize any interactive features here

    const navLinks = document.querySelectorAll('nav a');

    if (navLinks.length) {
        navLinks.forEach(link => {
            link.addEventListener('click', (event) => {
                // Use the link reference instead of event.target (which may be a child element)
                const href = link.getAttribute('href') || '';
                // Only intercept same-page anchors (href starting with '#')
                if (!href.startsWith('#')) return;
                event.preventDefault();

                const targetId = href.substring(1);
                const targetSection = document.getElementById(targetId);

                if (targetSection) {
                    // Calculate absolute position for smooth scrolling
                    const top = targetSection.getBoundingClientRect().top + window.pageYOffset;
                    window.scrollTo({
                        top,
                        behavior: 'smooth'
                    });
                }
            });
        });
    }

    // Example of a form submission handler
    const contactForm = document.getElementById('contact-form');
    if (contactForm) {
        contactForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const formData = new FormData(contactForm);
            // Convert FormData to an object safely
            console.log('Form submitted:', Object.fromEntries(formData.entries()));
        });
    }
});