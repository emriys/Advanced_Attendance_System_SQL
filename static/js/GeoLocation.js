window.onload = function () {
    getUserPermission();
}
let latitude = null;
let longitude = null;
let permitted = false;

async function getUserPermission() {
    if ("geolocation" in navigator) {
        navigator.geolocation.getCurrentPosition(
            (position) => {
                permitted = true;
                latitude = position.coords.latitude;
                longitude = position.coords.longitude;
                accuracy = position.coords.accuracy;
                // console.log(`Permitted: ${permitted}`);
            },
            (error) => {
                console.error("Error getting location:", error.message);
            },
            {
                enableHighAccuracy: true, // Improves accuracy using GPS & Wi-Fi
                timeout: 10000, // Max time to wait (10 seconds)
                maximumAge: 0, // No cached position
            }
        );
    }
}

async function getUserLocation() {
    return new Promise(async function (resolve, reject) {
            if (!navigator.geolocation) {
                console.error("Geolocation is not supported by this browser.");
                alert("Geolocation is not supported by this browser. Please use a different browser.");
                reject("Geolocation not supported.");
                return;
            }

            navigator.geolocation.getCurrentPosition(
                (position) => {
                    latitude = position.coords.latitude;
                    longitude = position.coords.longitude;
                    accuracy = position.coords.accuracy;
                    // console.log(`Latitude: ${latitude}, Longitude: ${longitude}, Accuracy: ${accuracy}`);
                    resolve({ latitude, longitude });
                },
                (error) => {
                    console.error("Error getting location:", error.message);
                    alert("Location access is required for logging. Please enable location in your browser settings.");
                    reject(error); // Reject on error
                },
                {
                    enableHighAccuracy: true, // Improves accuracy using GPS & Wi-Fi
                    timeout: 10000, // Max time to wait (10 seconds)
                    maximumAge: 0, // No cached position
                }
            );
    });
}

async function searchLocation() {
    return new Promise(async function (resolve) {
        const address = document.getElementById('search').value;
        const formatted_address = encodeURIComponent(address);
        console.log("Formated Address: ", formatted_address);
        await fetch(`https://us1.locationiq.com/v1/search?key=pk.7bfec70f74e20ec024df714f9134008d&q=${formatted_address}&format=json&`)
            .then(response => response.json())
            .then(data => {
                const location = data[0];
                // console.log(data[0]);
                // console.log("Coordinates:", location.lat, location.lon);
                if (location.lat && location.lon) {
                    document.getElementById("displayCoord").innerHTML = `${location.lat},${location.lon}`;
                    resolve();
                }
                else {
                    document.getElementById("displayCoord").innerHTML = "Not found";
                    resolve();
                }
            })
            .catch(error => {
                console.error("Error fetching address:", error);
                document.getElementById("addressOutput").innerText = "Error retrieving address.";
                resolve();
            });
    });
}

async function getAddress(lat, lon) {
    return new Promise(async function (resolve) {
        // await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`)
        // https://nominatim.openstreetmap.org/ui/reverse.html?lat=7.43219&lon=3.89318&zoom=18
        await fetch(`https://us1.locationiq.com/v1/reverse?key=pk.7bfec70f74e20ec024df714f9134008d&lat=${lat}&lon=${lon}&format=json&`)
            // For Search Forward Geocoding 
            // https://us1.locationiq.com/v1/search?key=Your_API_Access_Token&q=&format=json&
            .then(response => response.json())
            .then(data => {
                // console.log("Address:", data);
                // console.log(data);
                if (data.display_name) {
                    document.getElementById("display").innerHTML = `${data.display_name}, ${lat},${lon}`;
                    resolve();
                }
                else {
                    document.getElementById("display").innerHTML = "Not found";
                    resolve();
                }
            })
            .catch(error => {
                console.error("Error fetching address:", error);
                document.getElementById("addressOutput").innerText = "Error retrieving address.";
                resolve();
            });
    });
}

async function getLocation(event) {
    event.preventDefault();
    await getUserLocation();
    await getAddress(latitude, longitude);
    const formData = new FormData;
    formData.append('lat', latitude);
    formData.append('long', longitude);

    fetch("/location", {
        method: 'POST',
        body: formData,
        headers: { "Accept": "application/json" }
    })
        .then((response) => {
            if (response.ok) {
                return response.json();
            } throw new Error('Server Error');
        })
        .then((data) => {
            msgArea(data.message);
            document.getElementById("distance").innerHTML = `${data.value} meters`;
        })
        .catch((error) => {
            msgArea('Failed to send location:', error);
        });
}