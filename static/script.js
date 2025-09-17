function account_settings() { // called when user clicks on account circle
    const dropdown = document.getElementById('account_options'); // this is the id of the dropdown element
    if (dropdown.style.display === 'block') { // flips betweeen block and none display
        dropdown.style.display = 'none'; // makes it hidden

    } else {
        dropdown.style.display = 'block'; // makes it block display, rather than hidden
    }
}

document.addEventListener('DOMContentLoaded',() => {
    const toggleButtonIcon = document.querySelector('.light-dark-mode');
    const body = document.body;

    window.toggle_mode = function() {
        const isLight = body.classList.toggle('light-theme');

        if (isLight) {
            toggleButtonIcon.textContent = 'dark_mode';
            localStorage.setItem('theme','light');
        } else {
            toggleButtonIcon.textContent = 'light_mode'
            localStorage.setItem('theme','dark');
        }
    }

    const savedTheme = localStorage.getItem('theme') || 'dark';

    if (savedTheme === "light") {
        body.classList.add('light-theme');
        toggleButtonIcon.textContent = 'dark_mode';
    } else {
        toggleButtonIcon.textContent = 'light_mode';
    }
})


document.addEventListener('DOMContentLoaded', function autosubmitfile() {
    const fileinput = document.getElementById('file-upload'); // gets file upload element
    const uploadform = document.getElementById('upload-form'); //gets upload form 
    const loadingdiv = document.getElementById('loading'); // gets the loading to show user so they know its actually doing something

    if (fileinput && uploadform) { // if both are true (meaning both have some value)
        // auto submit the upload form once it detects a change
        fileinput.addEventListener('change', function() { // change is when files uploaded to the website
            // check if files were selected
            if (fileinput.files.length > 0) { // if more than 0 files
                if (loadingdiv) { // if loading div exists (just incase something breaks please)
                    loadingdiv.style.display = 'block'; // makes the loading visble
                    uploadform.submit(); // submit the form when changes are detected and loading div is block
 
                }
            }
        });
    }
});
