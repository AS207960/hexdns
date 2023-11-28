use std::char;
use std::iter::Peekable;
use std::str::Bytes;

use trust_dns_client::error::*;
use trust_dns_client::serialize::txt::Token;

/// A Lexer for Zone files
pub struct Lexer<'a> {
    txt: Peekable<Bytes<'a>>,
    state: State,
}

impl<'a> Lexer<'a> {
    /// Creates a new lexer with the given data to parse
    pub fn new(txt: &str) -> Lexer<'_> {
        Lexer {
            txt: txt.bytes().peekable(),
            state: State::StartLine,
        }
    }

    /// Return the next Token in the string
    pub fn next_token(&mut self) -> LexerResult<Option<Token>> {
        let mut char_data_vec: Option<Vec<String>> = None;
        let mut char_data: Option<Vec<u8>> = None;

        for i in 0..4096 {
            // max chars in a single lex, helps with issues in the lexer...
            assert!(i < 4095); // keeps the bounds of the loop defined (nothing lasts forever)

            // This is to get around mutability rules such that we can peek at the iter without moving next...
            let ch: Option<u8> = self.peek();

            // handy line for debugging
            // debug!("ch = {:?}; state = {:?}(c: {:?}, v: {:?})", ch, self.state, char_data, char_data_vec);

            // continuing states should pass back the state as the last statement,
            //  terminal states should set the state internally and return the proper Token::*.
            // TODO: there is some non-ideal copying going on in here...
            match self.state {
                State::StartLine => {
                    match ch {
                        Some(b'\r') | Some(b'\n') => {
                            self.state = State::EOL;
                        }
                        // white space at the start of line is a Blank
                        Some(ch) if ch.is_ascii_whitespace() => self.state = State::Blank,
                        Some(_) => self.state = State::RestOfLine,
                        None => {
                            self.state = State::EOF;
                        }
                    }
                }
                State::RestOfLine => {
                    match ch {
                        Some(b'@') => self.state = State::At,
                        Some(b'(') => {
                            self.txt.next();
                            char_data_vec = Some(Vec::new());
                            self.state = State::List;
                        }
                        Some(ch @ b')') => return Err(LexerErrorKind::IllegalCharacter(ch as char).into()),
                        Some(b'$') => {
                            self.txt.next();
                            char_data = Some(Vec::new());
                            self.state = State::Dollar;
                        }
                        Some(b'\r') | Some(b'\n') => {
                            self.state = State::EOL;
                        }
                        Some(b'"') => {
                            self.txt.next();
                            char_data = Some(Vec::new());
                            self.state = State::Quote;
                        }
                        Some(b';') => self.state = State::Comment { is_list: false },
                        Some(ch) if ch.is_ascii_whitespace() => {
                            self.txt.next();
                        } // gobble other whitespace
                        Some(ch) if !ch.is_ascii_control() && !ch.is_ascii_whitespace() => {
                            char_data = Some(Vec::new());
                            self.state = State::CharData { is_list: false };
                        }
                        Some(ch) => return Err(LexerErrorKind::UnrecognizedChar(ch as char).into()),
                        None => {
                            self.state = State::EOF;
                        }
                    }
                }
                State::Blank => {
                    // consume the whitespace
                    self.txt.next();
                    self.state = State::RestOfLine;
                    return Ok(Some(Token::Blank));
                }
                State::Comment { is_list } => {
                    match ch {
                        Some(b'\r') | Some(b'\n') => {
                            self.state = if is_list { State::List } else { State::EOL };
                        } // out of the comment
                        Some(_) => {
                            self.txt.next();
                        } // advance the token by default and maintain state
                        None => {
                            self.state = State::EOF;
                        }
                    }
                }
                State::Quote => {
                    match ch {
                        // end and gobble the '"'
                        Some(b'"') => {
                            self.state = State::RestOfLine;
                            self.txt.next();
                            return Ok(Some(Token::CharData(
                                char_data.take().as_deref()
                                    .map(|s| String::from_utf8_lossy(s).to_string()).unwrap_or_else(|| "".into()),
                            )));
                        }
                        Some(b'\\') => {
                            Self::push_to_str(&mut char_data, self.escape_seq()?)?;
                        }
                        Some(ch) => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, ch)?;
                        }
                        None => return Err(LexerErrorKind::UnclosedQuotedString.into()),
                    }
                }
                State::Dollar => {
                    match ch {
                        // even this is a little broad for what's actually possible in a dollar...
                        Some(ch @ b'A'..=b'Z') => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, ch)?;
                        }
                        // finishes the Dollar...
                        Some(_) | None => {
                            self.state = State::RestOfLine;
                            let dollar: String = char_data.take().as_deref()
                                .map(|s| String::from_utf8_lossy(s).to_string()).ok_or_else(|| {
                                LexerError::from(LexerErrorKind::IllegalState(
                                    "char_data \
                                     is None",
                                ))
                            })?;

                            return Ok(Some(match dollar.as_str() {
                                "INCLUDE" => Token::Include,
                                "ORIGIN" => Token::Origin,
                                "TTL" => Token::Ttl,
                                _ => {
                                    return Err(LexerErrorKind::UnrecognizedDollar(
                                        char_data.take().as_deref()
                                            .map(|s| String::from_utf8_lossy(s).to_string()).unwrap_or_else(|| "".into()),
                                    )
                                        .into())
                                }
                            }));
                        }
                    }
                }
                State::List => match ch {
                    Some(b';') => {
                        self.txt.next();
                        self.state = State::Comment { is_list: true }
                    }
                    Some(b')') => {
                        self.txt.next();
                        self.state = State::RestOfLine;
                        return char_data_vec
                            .take()
                            .ok_or_else(|| {
                                LexerErrorKind::IllegalState("char_data_vec is None").into()
                            })
                            .map(|v| Some(Token::List(v)));
                    }
                    Some(ch) if ch.is_ascii_whitespace() => {
                        self.txt.next();
                    }
                    Some(ch) if !ch.is_ascii_control() && !ch.is_ascii_whitespace() => {
                        char_data = Some(Vec::new());
                        self.state = State::CharData { is_list: true }
                    }
                    Some(ch) => return Err(LexerErrorKind::UnrecognizedChar(ch as char).into()),
                    None => return Err(LexerErrorKind::UnclosedList.into()),
                },
                State::CharData { is_list } => {
                    match ch {
                        Some(ch @ b')') if !is_list => {
                            return Err(LexerErrorKind::IllegalCharacter(ch as char).into())
                        }
                        Some(ch) if ch.is_ascii_whitespace() || ch == b')' || ch == b';' => {
                            if is_list {
                                char_data_vec
                                    .as_mut()
                                    .ok_or_else(|| {
                                        LexerError::from(LexerErrorKind::IllegalState(
                                            "char_data_vec is None",
                                        ))
                                    })
                                    .and_then(|v| {
                                        let char_data = char_data.take().ok_or(
                                            LexerErrorKind::IllegalState("char_data is None"),
                                        )?;

                                        v.push(
                                            String::from_utf8_lossy(&char_data).to_string()
                                        );
                                        Ok(())
                                    })?;
                                self.state = State::List;
                            } else {
                                self.state = State::RestOfLine;
                                let result = char_data.take().ok_or_else(|| {
                                    LexerErrorKind::IllegalState("char_data is None").into()
                                });
                                let opt = result.map(|s| Some(
                                    Token::CharData(String::from_utf8_lossy(&s).to_string())
                                ));
                                return opt;
                            }
                        }
                        // TODO: this next one can be removed, but will keep unescaping for quoted strings
                        //Some('\\') => { try!(Self::push_to_str(&mut char_data, try!(self.escape_seq()))); },
                        Some(ch) if !ch.is_ascii_control() && !ch.is_ascii_whitespace() => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, ch)?;
                        }
                        Some(ch) => return Err(LexerErrorKind::UnrecognizedChar(ch as char).into()),
                        None => {
                            self.state = State::EOF;
                            return char_data
                                .take()
                                .ok_or_else(|| {
                                    LexerErrorKind::IllegalState("char_data is None").into()
                                })
                                .map(|s| Some(Token::CharData(
                                    String::from_utf8_lossy(&s).to_string())
                                ));
                        }
                    }
                }
                State::At => {
                    self.txt.next();
                    self.state = State::RestOfLine;
                    return Ok(Some(Token::At));
                }
                State::EOL => match ch {
                    Some(b'\r') => {
                        self.txt.next();
                    }
                    Some(b'\n') => {
                        self.txt.next();
                        self.state = State::StartLine;
                        return Ok(Some(Token::EOL));
                    }
                    Some(ch) => return Err(LexerErrorKind::IllegalCharacter(ch as char).into()),
                    None => return Err(LexerErrorKind::EOF.into()),
                },
                // to exhaust all cases, this should never be run...
                State::EOF => {
                    self.txt.next(); // making sure we consume the last... it will always return None after.
                    return Ok(None);
                }
            }
        }

        unreachable!("The above match statement should have found a terminal state");
    }

    fn push_to_str(collect: &mut Option<Vec<u8>>, ch: u8) -> LexerResult<()> {
        collect
            .as_mut()
            .ok_or_else(|| LexerErrorKind::IllegalState("collect is None").into())
            .map(|s| {
                s.push(ch);
            })
    }

    fn escape_seq(&mut self) -> LexerResult<u8> {
        // escaped character, let's decode it.
        self.txt.next(); // consume the escape
        let ch = self
            .peek()
            .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))?;

        if !ch.is_ascii_control() {
            if b'0' <= ch && ch <= b'9' {
                // in this case it's an escaped octal: \DDD
                let d1: u8 = self
                    .txt
                    .next()
                    .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))
                    .map(|c| {
                        (c as char).to_digit(10)
                            .map(|d| d as u8)
                            .ok_or_else(|| LexerError::from(LexerErrorKind::IllegalCharacter(c as char)))
                    })??; // gobble
                let d2: u8 = self
                    .txt
                    .next()
                    .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))
                    .map(|c| {
                        (c as char).to_digit(10)
                            .map(|d| d as u8)
                            .ok_or_else(|| LexerError::from(LexerErrorKind::IllegalCharacter(c as char)))
                    })??; // gobble
                let d3: u8 = self
                    .txt
                    .next()
                    .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))
                    .map(|c| {
                        (c as char).to_digit(10)
                            .map(|d| d as u8)
                            .ok_or_else(|| LexerError::from(LexerErrorKind::IllegalCharacter(c as char)))
                    })??; // gobble

                let val: u8 = (d1 * 100) + (d2 * 10) + d3;

                Ok(val)
            } else {
                // this is an escaped char: \X
                self.txt.next(); // gobble the char
                Ok(ch)
            }
        } else {
            Err(LexerErrorKind::IllegalCharacter(ch as char).into())
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.txt.peek().cloned()
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum State {
    StartLine,
    RestOfLine,
    Blank,                      // only if the first part of the line
    List,                       // (..)
    CharData { is_list: bool }, // [a-zA-Z, non-control utf8]+
    //  Name,              // CharData + '.' + CharData
    Comment { is_list: bool }, // ;.*
    At,                        // @
    Quote,                     // ".*"
    Dollar,                    // $
    EOL,                       // \n or \r\n
    EOF,
}