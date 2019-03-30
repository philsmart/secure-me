
package uk.ac.cardiff.nsa.security.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.PostConstruct;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/weather")
public class WeatherController {

    @Nonnull Map<String, WEATHER> weather;

    public enum WEATHER {
        SUN("Sun"), RAIN("Rain"), CLOUD("Cloud");

        private String name;

        WEATHER(@Nonnull final String weatherName) {
            name = Objects.requireNonNull(weatherName);
        }

        /**
         * @return Returns the name.
         */
        public String getName() {
            return name;
        }

    }

    /**
     * Create some mock weather values
     */
    @PostConstruct
    public void init() {
        weather = new HashMap<String, WEATHER>();
        weather.put("Cardiff", WEATHER.SUN);
        weather.put("London", WEATHER.CLOUD);
    }

    @RequestMapping(value = "{city}", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    public String getWeather(@PathVariable("city") final String city) {

        if (weather.containsKey(city)) {
            return weather.get(city).getName();
        }
        return null;
    }

}
