window.onload = () => {
    const dpicn= document.querySelector(".dpicn");
    const dropdown = document.querySelector(".dropdown");

    if (dpicn && dropdown) {
        dpicn.addEventListener("click", () => {
            dropdown.classList.toggle("dropdown-open");
        });
    }
};

