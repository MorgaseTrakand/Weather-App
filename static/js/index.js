const apiKey = "d883e5b884ce3be7d176de233358e1a4";
const apiUrl = "https://api.openweathermap.org/data/2.5/weather?&units=imperial&q=";
const hourlyUrl = "https://pro.openweathermap.org/data/2.5/forecast/hourly?&units=imperial&q=";

const searchBar = document.querySelector("#searchBar");
const card2 = document.querySelector(".second-day");
const card3 = document.querySelector(".third-day");
const card4 = document.querySelector(".fourth-day");

const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const monthLength = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const date = new Date();
function isLeapYear(year) {
    return (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0));
}


function dateConvertor(daysAfter) {
    var day = date.getDate() + daysAfter;
    var month = date.getMonth() + 1;
    let year = date.getFullYear();
    if (isLeapYear(year) && month === 2) {
        monthLength[2] = 29;
    } else {
        monthLength[2] = 28;
    }
    if (day > monthLength[month]) {
        month++;
        if (month = 13) {
            month = 1;
        }
        day = day - monthLength[month] - 1;
    }
    return (month + "/" + (day));
};

card2.innerHTML = dateConvertor(2);
card3.innerHTML = dateConvertor(3);
card4.innerHTML = dateConvertor(4);

async function checkWeather(city)
{
    const response = await fetch(apiUrl + city + `&appid=${apiKey}`);
    if (!response.ok) {
        window.alert(city + " is not a valid entry")
    }
    var data = await response.json();
    console.log(data);

    const hourlyRes = await fetch(hourlyUrl + city + `&appid=${apiKey}`);
    var hourlyFor = await hourlyRes.json();
    console.log(hourlyFor);

    var latitude = data.coord.lat;
    var longitude = data.coord.lon;

    const rainUrl = "https://api.open-meteo.com/v1/forecast?latitude=" + latitude + "&longitude=" + longitude + "&hourly=temperature_2m,precipitation_probability,weathercode&temperature_unit=fahrenheit&windspeed_unit=mph&precipitation_unit=inch&timezone=GMT&forecast_days=2"
    const rainRes = await fetch(rainUrl)
    var hourlyForc = await rainRes.json();
    console.log(hourlyForc);
    precipitation = hourlyForc.hourly.precipitation_probability;
    hourlyTemp = hourlyForc.hourly.temperature_2m;

    var tzOffset = data.timezone;
    

    var timeSpan = document.querySelector(".message");
    var now = new Date();
    let hours = now.getHours();
    
    var convHours = hours - (tzOffset/3600);
    console.log(convHours)

    document.querySelector(".rain").innerHTML = precipitation[convHours] + "%";
    document.querySelector(".hour1").innerHTML = Math.round(hourlyTemp[convHours + 1]) + "°"
    document.querySelector(".hour2").innerHTML = Math.round(hourlyTemp[convHours + 2])+ "°"
    document.querySelector(".hour3").innerHTML = Math.round(hourlyTemp[convHours + 3]) + "°"
    document.querySelector(".hour4").innerHTML = Math.round(hourlyTemp[convHours + 4]) + "°"


    if (hours > 5 && hours < 11) {
        message = "Good Morning";
    }
    else if (hours >= 11 && hours < 17) {
        message = "Good Afternoon";
    }
    else {
        message = "Good Night"
    }
    timeSpan.innerHTML = message;
    let minutes = now.getMinutes();
    const amOrPm = hours >= 12 ? 'PM' : 'AM';    
    hours = hours % 12;
    hours = hours || 12;
    minutes = minutes < 10 ? `0${minutes}` : minutes;
    const formattedTime = `${hours}:${minutes} ${amOrPm}`;
    document.querySelector(".current-time").innerHTML = formattedTime;

    document.querySelector(".location").innerHTML = data.name;
    let windNum = data.wind.speed;
    windSpeed = windNum.toFixed(1)
    windSpeed = windSpeed + "mph"
    document.querySelector(".wind").innerHTML = windSpeed;

    function transformString(str) {
        return str.toLowerCase().split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
    }
    var currentDescription = document.querySelectorAll(".condition");
    currentDescription.forEach(function(tempElement) {
        var upperCase = data.weather[0].description;
        tempElement.innerHTML = transformString(upperCase)
    });
    var currentTemps = document.querySelectorAll(".current-temp");
    currentTemps.forEach(function(tempElement) {
        tempElement.innerHTML = Math.round(data.main.temp) + "°F";
    });
    nextTemp1 = document.querySelector(".next-temp1");
    nextTemp2 = document.querySelector(".next-temp2");
    nextTemp3 = document.querySelector(".next-temp3");
    nextTemp4 = document.querySelector(".next-temp4");

    nextTemp1.innerHTML = Math.round(hourlyFor.list[1].main.temp) + "°F";
    nextTemp2.innerHTML = Math.round(hourlyFor.list[2].main.temp) + "°F";
    nextTemp3.innerHTML = Math.round(hourlyFor.list[3].main.temp) + "°F";
    nextTemp4.innerHTML = Math.round(hourlyFor.list[4].main.temp) + "°F";

    nextDesc1 = document.querySelector(".next-desc1");
    nextDesc2 = document.querySelector(".next-desc2");
    nextDesc3 = document.querySelector(".next-desc3");
    nextDesc4 = document.querySelector(".next-desc4");

    nextDesc1.innerHTML = hourlyFor.list[1].weather[0].main;
    nextDesc2.innerHTML = hourlyFor.list[2].weather[0].main;
    nextDesc3.innerHTML = hourlyFor.list[3].weather[0].main;
    nextDesc4.innerHTML = hourlyFor.list[4].weather[0].main;


    var tl = gsap.timeline();
    tl.to(".preloader", { duration: 0.2, ease: "power1", autoAlpha: 0, })
    tl.from(".logo", { y: -150, opacity: 0, duration: 0.6, ease: "power1" }, 0);
    tl.from(".search-location", { y: -150, opacity: 0, duration: 0.6, ease: "power1" }, 0.1);
    tl.from(".login-button", { y: -150, opacity: 0, duration: 0.6, ease: "power1" }, 0.2);
    tl.from(".main-temp", { y: 50, opacity: 0, duration: 0.4, ease: "power1" }, 0.3)
    tl.from(".main-condition", { y: 50, opacity: 0, duration: 0.4, ease: "power1" }, 0.3)
    tl.from(".c-three-container-one", { x: 50, duration: 0.4, ease: "power1", opacity: 0 }, 0.4);
    tl.from(".c-three-container-two", { x: 50, duration: 0.4, ease: "power1", opacity: 0 }, 0.4);
    tl.from(".current-location", { y: -50, duration: 0.4, ease: "power1", opacity: 0 }, 0.3);
    tl.from(".c1", { y: 50, duration: 0.4, ease: "power1", opacity: 0 }, 0.1);
    tl.from(".c2", { y: 50, duration: 0.4, ease: "power1", opacity: 0 }, 0.2);
    tl.from(".c3", { y: 50, duration: 0.4, ease: "power1", opacity: 0 }, 0.3);
    tl.from(".c4", { y: 50, duration: 0.4, ease: "power1", opacity: 0 }, 0.4);
}
    
    
searchBar.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      checkWeather(searchBar.value);
    }
});
checkWeather("New York")

async function reverseGeo() {
    const response = await fetch("https://api.bigdatacloud.net/data/reverse-geocode-client");
    var res = await response.json();
    console.log(res);
    var city = res.city;
    console.log(city);
    checkWeather(city);
}  

const locationButton = document.querySelector(".location-b");
function handleGeoLocation() {
    if ("geolocation" in navigator) { // Check if the browser supports Geolocation
        navigator.geolocation.getCurrentPosition(function(position) {
            reverseGeo()
        }, function(error) {
            console.error("Error occurred:", error.message);
        });
    } else {
        console.error("Geolocation is not supported by this browser.");
    }
};
locationButton.addEventListener('click', handleGeoLocation);

usernameBox = document.getElementById("username");
usernameBox.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      usernameBox.style.backgroundColor = "white";
    }
});

checkWeather("New York")
var loginButton = document.querySelector(".login-button");
loginButton.addEventListener('mouseenter', function(event) {
    gsap.to("")
    loginButton.addEventListener('mouseleave', function(event) {

    });
});