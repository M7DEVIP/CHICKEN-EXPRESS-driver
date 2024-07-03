import 'package:flutter/material.dart';
import 'orders_page.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Tasleem',
      theme: ThemeData(
        primarySwatch: Colors.deepPurple,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: const HomePage(
          userName: "Mohammed", token: ""), // أضف المعامل هنا للاختبار
    );
  }
}

class HomePage extends StatefulWidget {
  final String userName;
  final String token; // إضافة التوكن
  const HomePage({super.key, required this.userName, required this.token});

  @override
  HomePageState createState() => HomePageState();
}

class HomePageState extends State<HomePage> {
  int _selectedIndex = 0;
  bool isAvailable = true;
  String userImageUrl =
      "https://example.com/user_image.jpg"; // رابط صورة المستخدم

  final List<Widget> _pages = [
    const DashboardPage(),
    const OrdersPage(),
    const EarningsPage(),
  ];

  void _onItemTapped(int index) {
    setState(() {
      _selectedIndex = index;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: PreferredSize(
        preferredSize: const Size.fromHeight(60.0), // تقليل ارتفاع التوب بار
        child: AppBar(
          backgroundColor: Colors.black,
          iconTheme: const IconThemeData(color: Colors.white),
          leading: Builder(
            builder: (BuildContext context) {
              return Center(
                child: IconButton(
                  icon: const Icon(Icons.menu),
                  onPressed: () {
                    Scaffold.of(context).openDrawer();
                  },
                  tooltip:
                      MaterialLocalizations.of(context).openAppDrawerTooltip,
                ),
              );
            },
          ),
          title: Center(
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  widget.userName,
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                Row(
                  children: [
                    Stack(
                      children: [
                        IconButton(
                          icon: const Icon(Icons.notifications,
                              color: Colors.white),
                          onPressed: () {
                            // Action for notifications
                          },
                        ),
                        Positioned(
                          right: 11,
                          top: 11,
                          child: Container(
                            padding: const EdgeInsets.all(2),
                            decoration: BoxDecoration(
                              color: Colors.red,
                              borderRadius: BorderRadius.circular(6),
                            ),
                            constraints: const BoxConstraints(
                              minWidth: 18,
                              minHeight: 18,
                            ),
                            child: const Text(
                              '3',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                              ),
                              textAlign: TextAlign.center,
                            ),
                          ),
                        ),
                      ],
                    ),
                    PopupMenuButton<String>(
                      onSelected: (value) {
                        setState(() {
                          isAvailable = value == 'available';
                        });
                      },
                      itemBuilder: (BuildContext context) {
                        return {'available', 'unavailable'}
                            .map((String choice) {
                          return PopupMenuItem<String>(
                            value: choice,
                            child: Text(choice == 'available'
                                ? 'Available'
                                : 'Unavailable'),
                          );
                        }).toList();
                      },
                      icon: AnimatedSwitcher(
                        duration: const Duration(milliseconds: 300),
                        transitionBuilder:
                            (Widget child, Animation<double> animation) {
                          return ScaleTransition(
                              scale: animation, child: child);
                        },
                        child: Icon(
                          isAvailable ? Icons.check_circle : Icons.cancel,
                          key: ValueKey<bool>(isAvailable),
                          color: isAvailable ? Colors.green : Colors.red,
                        ),
                      ),
                    ),
                    PopupMenuButton<String>(
                      onSelected: (value) {
                        if (value == 'logout') {
                          // تنفيذ تسجيل الخروج
                        }
                      },
                      itemBuilder: (BuildContext context) {
                        return [
                          PopupMenuItem<String>(
                            value: 'profile',
                            child: Text(widget.userName), // عرض اسم المستخدم
                          ),
                          const PopupMenuItem<String>(
                            value: 'logout',
                            child: Text('Logout'),
                          ),
                        ];
                      },
                      child: const Icon(Icons.more_vert, color: Colors.white),
                    ),
                  ],
                ),
              ],
            ),
          ),
          actions: const [
            SizedBox(width: 20), // إضافة مسافة لجعل الأيقونات متناسقة
          ],
        ),
      ),
      drawer: Drawer(
        child: Container(
          color: Colors.black,
          child: ListView(
            padding: EdgeInsets.zero,
            children: <Widget>[
              UserAccountsDrawerHeader(
                accountName: Text(widget.userName),
                accountEmail: const Text("example@mail.com"),
                currentAccountPicture: CircleAvatar(
                  backgroundImage: userImageUrl.isNotEmpty
                      ? NetworkImage(userImageUrl)
                      : const AssetImage('assets/def-user.png'),
                ),
                decoration: const BoxDecoration(
                  color: Colors.black,
                ),
              ),
              ListTile(
                leading: const Icon(Icons.dashboard, color: Colors.white),
                title: const Text('Dashboard',
                    style: TextStyle(color: Colors.white)),
                onTap: () {
                  Navigator.pop(context);
                  _onItemTapped(0);
                },
              ),
              ListTile(
                leading: const Icon(Icons.list_alt, color: Colors.white),
                title:
                    const Text('Orders', style: TextStyle(color: Colors.white)),
                onTap: () {
                  Navigator.pop(context);
                  _onItemTapped(1);
                },
              ),
              ListTile(
                leading: const Icon(Icons.location_on, color: Colors.white),
                title: const Text('Location',
                    style: TextStyle(color: Colors.white)),
                onTap: () {
                  Navigator.pop(context);
                  _onItemTapped(2);
                },
              ),
              ListTile(
                leading: const Icon(Icons.attach_money, color: Colors.white),
                title: const Text('Earnings',
                    style: TextStyle(color: Colors.white)),
                onTap: () {
                  Navigator.pop(context);
                  _onItemTapped(2);
                },
              ),
            ],
          ),
        ),
      ),
      body: _pages[_selectedIndex],
      bottomNavigationBar: BottomNavigationBar(
        items: const <BottomNavigationBarItem>[
          BottomNavigationBarItem(
            icon: Icon(Icons.home, size: 30),
            label: 'Home',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.list_alt, size: 30),
            label: 'Orders',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.location_on, size: 30),
            label: 'Location',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.person, size: 30),
            label: 'Profile',
          ),
        ],
        currentIndex: _selectedIndex,
        selectedItemColor: Colors.deepPurple,
        unselectedItemColor: Colors.grey,
        backgroundColor: Colors.black,
        type: BottomNavigationBarType.fixed,
        showSelectedLabels: true,
        showUnselectedLabels: false,
        onTap: _onItemTapped,
      ),
    );
  }
}

class DashboardPage extends StatelessWidget {
  const DashboardPage({super.key});

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text(
        'Dashboard Page',
        style: TextStyle(fontSize: 24),
      ),
    );
  }
}

class EarningsPage extends StatelessWidget {
  const EarningsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text(
        'Earnings Page',
        style: TextStyle(fontSize: 24),
      ),
    );
  }
}
