package uk.ac.cardiff.nsa.security.token;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by philsmart on 15/03/2017.
 */
@Component
public class TokenRepository {


    /**
     * All tokens in this list are assumed valid e.g. belongs to authenticated client users.
     */
    private List<SimpleToken> publishedTokens = new ArrayList<SimpleToken>();


    public List<SimpleToken> getPublishedTokens() {
        return publishedTokens;
    }


}



