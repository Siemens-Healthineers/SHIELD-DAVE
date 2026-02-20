/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

document.addEventListener('DOMContentLoaded', function() {
    // Initialize profile dropdown
    initProfileDropdown();
    
    // Initialize navigation
    initNavigation();
});

/**
 * Initialize Profile Dropdown Functionality
 */
function initProfileDropdown() {
    const trigger = document.getElementById('profile-trigger');
    const menu = document.getElementById('profile-menu');
    const arrow = document.querySelector('.profile-arrow');
    let isOpen = false;
    
    if (trigger && menu && arrow) {
        trigger.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            if (isOpen) {
                closeProfileDropdown();
            } else {
                openProfileDropdown();
            }
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            if (!trigger.contains(e.target) && !menu.contains(e.target)) {
                if (isOpen) {
                    closeProfileDropdown();
                }
            }
        });
        
        // Close dropdown on escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && isOpen) {
                closeProfileDropdown();
            }
        });
    }
    
    function openProfileDropdown() {
        const menu = document.getElementById('profile-menu');
        const arrow = document.querySelector('.profile-arrow');
        
        if (menu && arrow) {
            menu.style.display = 'block';
            arrow.style.transform = 'rotate(180deg)';
            isOpen = true;
            
            // Add animation
            setTimeout(() => {
                menu.classList.add('show');
            }, 10);
        }
    }
    
    function closeProfileDropdown() {
        const menu = document.getElementById('profile-menu');
        const arrow = document.querySelector('.profile-arrow');
        
        if (menu && arrow) {
            menu.classList.remove('show');
            arrow.style.transform = 'rotate(0deg)';
            isOpen = false;
            
            // Hide after animation
            setTimeout(() => {
                if (!isOpen) {
                    menu.style.display = 'none';
                }
            }, 200);
        }
    }
}

/**
 * Initialize Navigation Functionality
 */
function initNavigation() {
    // Add loading states to navigation links
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(function(item) {
        item.addEventListener('click', function(e) {
            // Don't add loading state to external links or current page
            if (this.target === '_blank' || this.classList.contains('active')) {
                return;
            }
            
            this.classList.add('loading');
            
            // Remove loading state after a delay (in case navigation is slow)
            setTimeout(() => {
                this.classList.remove('loading');
            }, 5000);
        });
    });
    
    // Handle navigation state restoration
    const currentPath = window.location.pathname;
    const currentNavItem = document.querySelector(`.nav-item[href="${currentPath}"]`);
    
    if (currentNavItem) {
        // Remove active class from all items
        navItems.forEach(item => item.classList.remove('active'));
        // Add active class to current item
        currentNavItem.classList.add('active');
    }
}

/**
 * Utility function to show loading state on any element
 */
function showLoading(element) {
    if (element) {
        element.classList.add('loading');
    }
}

/**
 * Utility function to hide loading state on any element
 */
function hideLoading(element) {
    if (element) {
        element.classList.remove('loading');
    }
}

/**
 * Utility function to update notification badge count
 */
function updateNotificationBadge(count) {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    }
}

/**
 * Utility function to update user info in header
 */
function updateUserInfo(userData) {
    const profileName = document.querySelector('.profile-name');
    const profileRole = document.querySelector('.profile-role');
    const profileNameLarge = document.querySelector('.profile-name-large');
    const profileEmail = document.querySelector('.profile-email');
    const profileRoleBadge = document.querySelector('.profile-role-badge');
    
    if (profileName && userData.username) {
        profileName.textContent = userData.username;
    }
    
    if (profileRole && userData.role) {
        profileRole.textContent = userData.role;
    }
    
    if (profileNameLarge && userData.username) {
        profileNameLarge.textContent = userData.username;
    }
    
    if (profileEmail && userData.email) {
        profileEmail.textContent = userData.email;
    }
    
    if (profileRoleBadge && userData.role) {
        profileRoleBadge.textContent = userData.role;
    }
}
