
# Unofficial Instagram WebAPI

> It was created for educational purposes only.
---

A reverse-engineered implementation of the [Instagram](https://www.instagram.com/) web app's API.

## Installation

```bash
dotnet add package InstaWebAPI
```

## Usage

### Creating an instance

```c#
using InstaWebAPI;
using InstaWebAPI.UserDate;

public class Program
{
	public static void Main()
	{
        UserDate user = new UserDate {
            Username = "username of account",
            Password = "password of account"
        };
        // If use default useragent = InstaWebAPI api = new InstaWebAPI(user);
		InsaWebAPI api = new InsaWebAPI(user, true, "useragent");
	}
}

```

### Instance methods

* [.DoLogin()](#DoLogin)
* [.GetUserProfileByUsernameAsync()](#GetUserProfileByUsernameAsync)
* [.GetChallengeRequestByChallengeUrlAsync()](#GetChallengeRequestByChallengeUrlAsync)
* [.GetChallengeRequestAsync()](#GetChallengeRequestAsync)
* [.ReplyChallengeByChoiceAsync()](#ReplyChallengeByChoiceAsync)
* [.GetFriendshipRelationByUsernameAsync()](#GetFriendshipRelationByUsernameAsync)
* [.GetUserBySearchBarAsync()](#GetUserBySearchBarAsync)
* [.GetUserIdByUsernameAsync()](#GetUserIdByUsernameAsync)
* [.FollowUserByIdAsync()](#FollowUserByIdAsync)
* [.UnfollowUserByIdAsync()](#UnfollowUserByIdAsync)
* [.GetSuspiciousLoginAsync()](#GetSuspiciousLoginAsync)
* [.GetMyProfileAsync()](#GetMyProfileAsync)
* [.UpdateProfileAsync()](#UpdateProfileAsync)
* [.AllowSuspiciosLoginByIdAsync()](#AllowSuspiciosLoginByIdAsync)
* [.GetMediaRelationByShortcodeAsync()](#GetMediaRelationByShortcodeAsync)
* [.LikeMediaByIdAsync()](#LikeMediaByIdAsync)
* [.UnlikeMediaByIdAsync()](#UnlikeMediaByIdAsync)
* [.CommentMediaByIdAsync()](#CommentMediaByIdAsync)

#### Exemple Usage

Authenticates you with the API and stores your session data in a CookieContainer.
Subsequent requests will include these cookies.
This Exemple do Login, Get User an Follow this user.

```c#
using InstaWebAPI;
using InstaWebAPI.UserDate;

public class Program
{
	public static void Main()
	{
        UserDate user = new UserDate {
            Username = "username of account",
            Password = "password of account"
        };
        // If use default useragent = InstaWebAPI api = new InstaWebAPI(user);
		InsaWebAPI api = new InsaWebAPI(user, true, "useragent");
        var login = api.DoLogin();
        if (login.Status == 1) {
            var user = api.GetUserBySearchBarAsync("username of target").Result;
            if (user.Status == 1) {
                var follow = api.FollowUserByIdAsync(user.Response).Result;
                if (follow.Status == 1) {
                    Console.WriteLine("Success");
                } else {
                    //Implement challeng check
                    Console.WriteLine("Follow user err");
                }
            } else {
                //Implement challeng check
                Console.WriteLine("Get user err");
            }
        } else {
            //Implement challeng check
            Console.WriteLine("Login err");
        }
	}
}
```

## Legal

This code is in no way affiliated with, authorized, maintained, sponsored or endorsed by Instagram
or any of its affiliates or subsidiaries. This is an independent and unofficial API. Use at your own risk.