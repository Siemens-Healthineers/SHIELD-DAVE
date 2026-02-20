/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

class ProfileDropdown {
    constructor() {
        this.dropdown = null;
        this.isOpen = false;
        this.init();
    }

    init() {
        // Add event listeners to existing dropdown
        this.addEventListeners();
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.profile-dropdown')) {
                this.close();
            }
        });
    }


    addEventListeners() {
        const trigger = document.getElementById('profile-trigger');
        const menu = document.getElementById('profile-menu');
        
        if (trigger && menu) {
            trigger.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.toggle();
            });
        }
    }

    toggle() {
        if (this.isOpen) {
            this.close();
        } else {
            this.open();
        }
    }

    open() {
        const menu = document.getElementById('profile-menu');
        const arrow = document.querySelector('.profile-arrow');
        
        if (menu && arrow) {
            menu.style.display = 'block';
            arrow.style.transform = 'rotate(180deg)';
            this.isOpen = true;
            
            // Add animation
            setTimeout(() => {
                menu.classList.add('show');
            }, 10);
        }
    }

    close() {
        const menu = document.getElementById('profile-menu');
        const arrow = document.querySelector('.profile-arrow');
        
        if (menu && arrow) {
            menu.classList.remove('show');
            arrow.style.transform = 'rotate(0deg)';
            this.isOpen = false;
            
            // Hide after animation
            setTimeout(() => {
                if (!this.isOpen) {
                    menu.style.display = 'none';
                }
            }, 200);
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ProfileDropdown();
});
